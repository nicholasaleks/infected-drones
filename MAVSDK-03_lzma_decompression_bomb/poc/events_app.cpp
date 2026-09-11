// Victim app for the COMPONENT_METADATA sink. No Camera plugin at all.
// EventsImpl::init() calls component_metadata().request_autopilot_component(),
// so MAVSDK asks for COMPONENT_METADATA on its own.
#include <mavsdk/mavsdk.h>
#include <mavsdk/plugins/events/events.h>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

int main(int argc, char** argv)
{
    if (argc < 2) { std::cerr << "usage: events_app <url> [seconds]\n"; return 2; }
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 60;
    mavsdk::Mavsdk mavsdk{mavsdk::Mavsdk::Configuration{mavsdk::ComponentType::GroundStation}};
    if (mavsdk.add_any_connection(argv[1]) != mavsdk::ConnectionResult::Success) {
        std::cerr << "[app] connection failed\n"; return 1;
    }
    std::cout << "[app] listening on " << argv[1] << std::endl;
    auto system = mavsdk.first_autopilot(30.0);
    if (!system) { std::cerr << "[app] no autopilot appeared\n"; return 1; }
    std::cout << "[app] system found. Creating the Events plugin -- no Camera plugin."
              << std::endl;
    auto events = mavsdk::Events{system.value()};
    for (int i = 0; i < seconds; ++i) std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout << "[app] exiting" << std::endl;
    return 0;
}
