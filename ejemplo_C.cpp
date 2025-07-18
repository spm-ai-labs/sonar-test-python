#include <iostream>
#include <cstring>
#include <cstdlib>

void autenticarUsuario(char* username, char* password) {
    char buffer[100];
    strcpy(buffer, username); // Vulnerabilidad: Buffer Overflow posible

    // Simulación de autenticación (comparar con credenciales hardcoded)
    if (strcmp(buffer, "admin") == 0 && strcmp(password, "admin123") == 0) {
        std::cout << "Acceso concedido" << std::endl;
    } else {
        std::cout << "Credenciales inválidas" << std::endl;
    }
}

void ejecutarComando(char* comando) {
    // Vulnerabilidad: Inyección de comandos
    std::string comandoCompleto = "sh -c \"" + std::string(comando) + "\"";
    system(comandoCompleto.c_str());
}

int main() {
    char username[100];
    char password[100];
    char comando[100];

    std::cout << "Ingrese usuario: ";
    std::cin >> username;
    std::cout << "Ingrese contraseña: ";
    std::cin >> password;

    autenticarUsuario(username, password);

    std::cout << "Ingrese comando a ejecutar: ";
    std::cin >> comando;
    ejecutarComando(comando);

    return 0;
}
