/**
 * Example of an UDP echo server and client using Simple UDP library.
 * The server listens for incoming messages and echoes them back to the sender.
 * 
 * Distributed under MIT Software License
 */
#include <udp/simple_udp.h>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define GREEN(x) "\033[32m" x "\033[0m"
#define BLUE(x)  "\033[34m" x "\033[0m"
#define RED(x)   "\033[31m" x "\033[0m"

#define SERVER_LOG(fmt, ...) printf( BLUE("UDP server " fmt "\n"), ##__VA_ARGS__)
#define CLIENT_LOG(fmt, ...) printf(GREEN("UDP client " fmt "\n"), ##__VA_ARGS__)

static std::atomic_bool g_is_running;

// close gracefully on Ctrl+C or SIGTERM by setting global running flag to false
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
    {
        printf("Signal %d received, shutting down...\n", signum);
        g_is_running = false;
    }
}

using time_source = std::chrono::system_clock;
using time_point = time_source::time_point;
using duration = time_source::duration;
using namespace std::chrono_literals;

static std::string format_time(const time_point& tp)
{
    time_t tt = time_source::to_time_t(tp);
    #if _MSC_VER
        struct tm local_tm;
        localtime_s(&local_tm, &tt); // convert to local time
    #else
        struct tm local_tm = *localtime(&tt);
    #endif
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_tm);
    return std::string(buffer);
}

/**
 * @brief A simple UDP echo server that listens on a specified port.
 *        It echoes back any received messages to the sender.
 * @param server_port The port on which the server will listen for incoming UDP packets.
 */
static void echo_server(int server_port)
{
    UdpSocket listener;
    if (!listener.create(server_port, /*blocking*/true))
    {
        g_is_running = false;
        throw std::runtime_error("UDP server creation failed");
    }

    SERVER_LOG("listening on port %d", server_port);
    while (g_is_running)
    {
        if (listener.poll_read(15))
        {
            while (listener.available() > 0)
            {
                char buffer[1024];
                IpAddress from;
                int bytes_received = listener.recvfrom(buffer, sizeof(buffer)-1, from);
                if (bytes_received > 0)
                {
                    buffer[bytes_received] = '\0';
                    SERVER_LOG("RCV from %15s:  %s", from.to_string().c_str(), buffer);

                     // echo back the received message
                    std::string response = "Echo: ";
                    response += buffer; // prepare echo response
                    listener.sendto(response.data(), response.size(), from);
                }
            }
        }
    }

    SERVER_LOG("closing down");
    listener.close();
}

/**
 * @brief A simple UDP client that starts sending timestamped messages to the server,
 *        and listens for any messages sent back by the server.
 * @param client_port Port of the client UDP socket.
 * @param server_address Address of the server where to send messages.
 */
static void client_runner(int client_port, IpAddress server_address)
{
    UdpSocket client;
    if (!client.create(client_port, /*blocking*/true))
    {
        g_is_running = false;
        throw std::runtime_error("UDP client creation failed");
    }

    CLIENT_LOG("created on port %d", client_port);
    duration message_interval = 1000ms; // send every 1 second
    time_point next_message_time = time_source::now() + message_interval;
    time_point until = time_source::now() + 10s; // send for 10 sec

    while (g_is_running)
    {
        auto now = time_source::now();
        if (now > until)
            break; // stop after time limit
        if (next_message_time <= now)
        {
            next_message_time = now + message_interval; // schedule next message

            // prepare message with current timestamp
            std::string message = format_time(now) + " -- Hello from UDP client";

            CLIENT_LOG("SND  to  %15s:  %s", server_address.to_string().c_str(), message.c_str());
            client.sendto(message.data(), message.size(), server_address);
        }
        if (client.poll_read(15))
        {
            while (client.available() > 0)
            {
                char buffer[1024];
                IpAddress from;
                int bytes_received = client.recvfrom(buffer, sizeof(buffer)-1, from);
                if (bytes_received > 0)
                {
                    buffer[bytes_received] = '\0';
                    CLIENT_LOG("RCV from %15s:  %s", from.to_string().c_str(), buffer);
                }
            }
        }
    }

    g_is_running = false; // stop client and server gracefully
    CLIENT_LOG("closing down");
    client.close();
}

int main(int argc, char* argv[])
{
    signal(SIGINT, &signal_handler);
    signal(SIGTERM, &signal_handler);

    const int server_port = 12345;
    const int client_port = 12346;
    g_is_running = true;
    std::future<void> server_task;

    try
    {
        server_task = std::async(std::launch::async, []
        {
            echo_server(server_port);
        });

        // allow server to start
        std::this_thread::sleep_for(15ms);

        // run client on main thread
        client_runner(client_port, IpAddress{"127.0.0.1", server_port});

        // wait for server to finish
        server_task.get();
    }
    catch (const std::exception& e)
    {
        g_is_running = false;
        fprintf(stderr, RED("Exception: %s") "\n", e.what());
        if (server_task.valid())
            server_task.wait(); // ensure server task is cleaned up
        return 1;
    }
    return 0;
}