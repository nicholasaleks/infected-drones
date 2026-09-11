// Minimal stand-in for a real MAVSDK-based ground station / companion app.
//
// The only thing that matters for MAVSDK-03 is that it instantiates the Camera
// plugin. CameraImpl's constructor subscribes process_heartbeat
// (camera_impl.cpp:78 in v3.17.4), and from then on ANY heartbeat from a new
// component id causes MAVSDK to request CAMERA_INFORMATION by itself
// (:1008 -> :1028). The app makes no further calls -- it just sits there.
#include <mavsdk/mavsdk.h>
#include <mavsdk/plugins/camera/camera.h>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "usage: gcs_app <connection_url> [seconds]\n";
        return 2;
    }
    const int seconds = (argc > 2) ? std::atoi(argv[2]) : 90;

    mavsdk::Mavsdk mavsdk{
        mavsdk::Mavsdk::Configuration{mavsdk::ComponentType::GroundStation}};

    if (mavsdk.add_any_connection(argv[1]) != mavsdk::ConnectionResult::Success) {
        std::cerr << "[app] connection failed\n";
        return 1;
    }
    std::cout << "[app] listening on " << argv[1] << ", waiting for a system..." << std::endl;

    auto system = mavsdk.first_autopilot(30.0);
    if (!system) {
        std::cerr << "[app] no autopilot appeared\n";
        return 1;
    }
    std::cout << "[app] system found. Creating the Camera plugin -- this is the ONLY\n"
              << "[app] thing the app does. No download is requested by the app." << std::endl;

    auto camera = mavsdk::Camera{system.value()};

    for (int i = 0; i < seconds; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << "[app] exiting" << std::endl;
    return 0;
}
