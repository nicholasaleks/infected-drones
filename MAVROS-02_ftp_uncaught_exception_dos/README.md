# MAVROS-02 — A MAVLink-FTP write-ack drives an unbounded `std::advance` into a heap read

| Field | Value |
|---|---|
| **Product** | [mavros](https://github.com/mavlink/mavros) (ROS 2 MAVLink ↔ ROS bridge), `ftp` plugin |
| **Severity** | **HIGH** — CVSS 3.1 **8.1** `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H` |
| **CWE** | CWE-125 (out-of-bounds read) · CWE-248 (uncaught exception) · CWE-617 (reachable assertion) · CWE-1284 (improper validation of specified quantity) |
| **Affected** | `ros2` branch and every 2.x release. Latest release 2.15.1; `ftp.cpp` is identical on the branch tip `7f7e8fdd` (2026-09-09) |
| **Fixed in** | nothing yet |
| **Verified** | 2.15.1 and branch tip `7f7e8fdd` for the source; runs were against the shipped `ros-jazzy-mavros` 2.14.0 Debian package (arm64, Release/NDEBUG) |
| **Interaction** | The operator starts an FTP upload. Everything after that is the vehicle's choice |
| **Platform** | Linux / ROS 2 |
| **Status** | Reproduced 2026-08-28 against the shipped package. **47,800 bytes of process memory returned to the attacker in one upload, including 168 pointer-shaped words, with the node still running.** Separately reproduced a whole-process `SIGABRT` from a single packet, and a `SIGSEGV` |
| **Advisory** | not filed |
| **Fix** | none opened |

---

## Summary

mavros lets the *vehicle* say how many bytes of a file upload it wrote, and uses that number as the
argument to `std::advance` on an iterator into a heap buffer. Two bounds checks sit in front of it,
and **both are compiled out of every shipped binary**: they use `rcpputils::assert_true`, which is
wrapped in `#ifndef NDEBUG`, and ROS 2 Debian packages are Release builds.

With the checks gone the iterator lands wherever the attacker points it. `write_bytes_to_copy()` then
computes a *negative* `std::distance`, which `std::min<size_t>` converts to the maximum chunk size,
and the next outgoing FTP message `std::copy`s 239 bytes from out of bounds — **back to the vehicle**.
Each subsequent ack advances another 239 bytes and the distance stays negative, so it never
self-corrects. It is a sequential memory scanner at 239 bytes per round trip.

A sibling check in the same file uses `rcpputils::require_true`, which is *not* NDEBUG-gated and
throws. Because the executor spins in a bare `std::thread` with no `try`/`catch`, that throw takes
down the whole process.

The honest cap: every route needs an operator-initiated FTP upload. Nothing here is push-triggered.

---

## Root cause

### 1. The vehicle chooses the advance

```cpp
// mavros/src/plugins/ftp.cpp:640-649
rcpputils::require_true(hdr->size == sizeof(uint32_t));
const size_t bytes_written = *req.data_u32();

// check that reported size not out of range
const size_t bytes_left_before_advance = std::distance(write_it, write_buffer.end());
rcpputils::assert_true(bytes_written <= bytes_left_before_advance, "Bad write size");
rcpputils::assert_true(bytes_written != 0);

// move iterator to written size
std::advance(write_it, bytes_written);
```

`bytes_written` is a `uint32` straight off the wire. The comment says the size is checked against the
range; the two lines that do it are the ones that disappear in a Release build.

### 2. Both bounds checks are compiled out

```cpp
// rcpputils/asserts.hpp
inline void assert_true(bool condition, const std::string & msg = "assertion failed")
{
// Same macro definition used by cassert
#ifndef NDEBUG
  if (!condition) {
    throw rcpputils::AssertionException{msg.c_str()};
  }
#else
  (void) condition;
  (void) msg;
#endif
}
```

Checked against the installed library rather than inferred from the header:

```
$ nm -DC /opt/ros/jazzy/lib/libmavros.so | grep -i AssertionException
  (none)
$ strings /opt/ros/jazzy/lib/libmavros.so | grep -c "Bad write size"
0
```

The message on the bounds check is not in the shipped binary at all.

### 3. The out-of-bounds distance becomes a maximum, not a minimum

```cpp
// mavros/src/plugins/ftp.cpp:1006-1011
size_t write_bytes_to_copy()
{
  return std::min<size_t>(
    std::distance(write_it, write_buffer.end()),
    FTPRequest::DATA_MAXSZ);
}
```

Once `write_it` is past `end()`, the `std::distance` is negative. Converted to `size_t` it is enormous,
so `std::min` returns `DATA_MAXSZ`. The function is meant to shrink the final chunk; past the end it
always returns a full one.

### 4. The out-of-bounds bytes are sent to the vehicle

```cpp
// mavros/src/plugins/ftp.cpp:772-776
FTPRequest req(FTPRequest::kCmdWriteFile, active_session);
req.header()->offset = write_offset;
req.header()->size = bytes_to_copy;
std::copy(write_it, write_it + bytes_to_copy, req.data());
req.send(uas, last_send_seqnr);
```

This is the disclosure. The read starts at the attacker's chosen offset and the result goes out over
MAVLink.

### 5. `require_true` is not gated, and nothing catches it

```cpp
// rcpputils/asserts.hpp
inline void require_true(bool condition, const std::string & msg = "invalid argument passed")
{
  if (!condition) {
    throw std::invalid_argument{msg};
  }
}
```

Live throw sites reached from vehicle-supplied header fields: `ftp.cpp:477` (NAK size),
`:577` (open ack size), `:640` (write ack size). And the executor:

```cpp
// mavros/src/lib/mavros_uas.cpp:115-126
exec_spin_thd = thread_ptr(
  new std::thread(
    [this]() {
      utils::set_this_thread_name("uas-exec/%d.%d", source_system, source_component);
      auto lg = this->get_logger();

      RCLCPP_INFO(
        lg, "UAS Executor started, threads: %zu",
        this->exec.get_number_of_threads());
      this->exec.spin();
      RCLCPP_WARN(lg, "UAS Executor terminated");
    }),
```

No `try`/`catch` anywhere in the lambda, so an escaping exception reaches `std::terminate` and aborts
the process rather than the thread.

### 6. A third sink in the list path

```cpp
// mavros/src/plugins/ftp.cpp:842-847
if (sep_it != name_size.end()) {
  name_size.erase(name_size.begin(), sep_it + 1);
  if (name_size.size() != 0) {
    ent.size = std::stoi(name_size);
  }
}
```

`std::stoi` on a vehicle-supplied token throws `std::invalid_argument` on a non-numeric string and
`std::out_of_range` on an oversized one. Same missing `try`/`catch`, same outcome.

---

## Taint trace

```
[operator] /mavros/ftp/open then /mavros/ftp/write        <- the one required action
   v
[wire]  FILE_TRANSFER_PROTOCOL ack, attacker-controlled payload
   v
handle_ack_write()
   |-- require_true(hdr->size == 4)                        ftp.cpp:640   throws -> SIGABRT
   |-- bytes_written = *req.data_u32()                     ftp.cpp:641   attacker's uint32
   |-- assert_true(bytes_written <= bytes_left, ...)       ftp.cpp:645   COMPILED OUT
   |-- assert_true(bytes_written != 0)                     ftp.cpp:646   COMPILED OUT
   '-- std::advance(write_it, bytes_written)               ftp.cpp:649   UNBOUNDED
         v
       write_bytes_to_copy()                               ftp.cpp:1006
         std::distance is negative -> size_t -> min() returns DATA_MAXSZ (239)
         v
       std::copy(write_it, write_it + 239, req.data())     ftp.cpp:775
       req.send(...)                                       ftp.cpp:776
         ===> 239 bytes of heap, from the attacker's offset, sent to the vehicle
         ===> the next ack advances another 239; distance stays negative, so it repeats

other throwing sinks reached the same way, all fatal for the process:
   require_true, NAK size                                  ftp.cpp:477
   require_true, open ack size                             ftp.cpp:577
   std::stoi on a list entry's size token                  ftp.cpp:845
   executor runs in a bare std::thread, no try/catch       mavros_uas.cpp:115-126
```

---

## Preconditions

| Condition | Default? | Notes |
|---|---|---|
| MAVLink link mavros is bound to | n/a | The attacker answers as the vehicle |
| `ftp` plugin loaded | **Yes** | Declared in `mavros_plugins.xml`; loaded by default |
| **Operator starts an FTP upload** | **Operator action** | `/mavros/ftp/open` then `/mavros/ftp/write`. This is the cap on the whole finding |
| Release build | **Yes** | ROS 2 Debian packages are Release, so `assert_true` is compiled out |
| The ack echoes `hdr->offset` | attacker must do it | `handle_ack_write` compares it against `write_offset` and bails otherwise |

---

## Impact

Three outcomes, all reproduced against the shipped package.

**Memory disclosure.** 47,800 bytes of process memory returned to the attacker in one upload, in 200
chunks of 239 bytes, with the node still running afterwards. 168 of the returned words were
pointer-shaped — live addresses such as `0x0000ffff9a1fe2d0` and `0x0000fff07ff90b30`, the latter with
the shape of a stack address, which is an ASLR defeat. The run stopped at 200 chunks only because the
harness stopped asking; `std::distance` stays negative, so mavros would have continued.

**Whole-process abort.** One malformed open-ack, `size = 7`, makes `require_true` throw
`std::invalid_argument`, which nothing catches: `terminate called after throwing an instance of
'std::invalid_argument'`, and the node is gone.

**Segmentation fault.** Walking the iterator into unmapped memory instead yields `SIGSEGV`.

Bounding it:

| Claim | Holds? | Why |
|---|---|---|
| Remote out-of-bounds read | **Yes** | 47,800 B measured, at an attacker-chosen offset |
| Contents reach the attacker | **Yes** | copied into the outgoing FTP message and sent over MAVLink |
| Sequential and repeatable | **Yes** | each ack advances 239 B; the distance stays negative so it never recovers |
| ASLR defeat | **Yes** | 168 pointer-shaped words in one run |
| Silent, no crash to alert the operator | **Yes** | the disclosure run left the node running |
| One-packet whole-process abort | **Yes** | `require_true` is not NDEBUG-gated, and the executor has no `try`/`catch` |
| Zero-click | **No** | it needs an operator-initiated FTP upload |
| Write or code execution | **No** | this is a read; nothing out-of-bounds is written |
| Attacker chooses the contents | **No** | the attacker positions the read, not what happens to be there |
| Reproducible on a Debug build | **No** | `assert_true` fires there and throws, so you get the abort instead of the leak |

---

## Version scope

| Version | NAK size | list entries | open ack | write ack | `advance` | `std::copy` | `std::stoi` |
|---|---|---|---|---|---|---|---|
| `ros2` tip `7f7e8fdd` | `:477` | `:565` | `:577` | `:640` | `:649` | `:775` | `:845` |
| 2.15.1 (latest release) | `:477` | `:565` | `:577` | `:640` | `:649` | `:775` | `:845` |
| 2.14.0 (tested) | `:461` | `:550` | `:562` | `:625` | `:634` | `:757` | `:829` |

`ftp.cpp` is byte-identical between 2.15.1 and the branch tip.

---

## Reproduction

Authorized bench only. Requires Docker and `pymavlink`.

```bash
cd poc
./run.sh                  # the disclosure run
./run.sh --overflow       # the std::out_of_range variant
```

The harness is the vehicle: mavros connects out to it, the operator calls `/mavros/ftp/open` and
`/mavros/ftp/write`, and the harness answers the write-acks with a `bytes_written` that walks the
iterator past the end of the buffer. It then prints the out-of-bounds bytes mavros hands back.

Two things cost real time and are worth knowing before you run it:

- **The ack must echo `hdr->offset`.** `handle_ack_write` compares the reply's offset against
  `write_offset` and bails with `EBADE` otherwise. An ack with `offset = 0` yields exactly one
  out-of-bounds chunk per operation instead of a continuous stream.
- **Where you land decides what you get.** Walking forward from an 8 KB buffer crosses untouched zero
  pages: the disclosure is real but the contents are dull. A 64-byte buffer sits in the main arena
  among live objects, and the same walk returns pointers. The disclosure is deterministic; its
  contents are heap-layout dependent.
