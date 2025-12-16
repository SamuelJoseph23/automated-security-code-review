#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <openssl/md5.h> // Simulating weak crypto usage

using namespace std;

// VULNERABLE: Hardcoded Secret (CRITICAL)
#define API_KEY "sk_live_1234567890abcdef"
#define DB_PASSWORD "super_secret_db_pass"

void process_user_input(char* user_input) {
    char buffer[50];
    
    // VULNERABLE: Buffer Overflow (CRITICAL)
    // strcpy doesn't check buffer size
    strcpy(buffer, user_input);
    
    // VULNERABLE: Buffer Overflow (CRITICAL)
    // gets is extremely dangerous and deprecated
    char input_buf[100];
    printf("Enter more data: ");
    gets(input_buf);
    
    printf("Processing: %s\n", buffer);
}

void execute_system_command(char* filename) {
    char command[256];
    
    // VULNERABLE: Command Injection (CRITICAL)
    // Unsanitized input used in system()
    sprintf(command, "cat %s", filename);
    system(command);
    
    // VULNERABLE: Command Injection (CRITICAL)
    // popen is also dangerous
    FILE* fp = popen(command, "r");
    pclose(fp);
}

void database_query(char* username) {
    char query[512];
    
    // VULNERABLE: SQL Injection (CRITICAL)
    // Formatting string directly into SQL query
    sprintf(query, "SELECT * FROM users WHERE username = '%s'", username);
    
    // Simulating database execution
    printf("Executing query: %s\n", query);
}

void weak_hashing(char* password) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    
    // VULNERABLE: Weak Cryptography (HIGH)
    // MD5 is broken and shouldn't be used for passwords
    MD5((unsigned char*)password, strlen(password), digest);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    process_user_input(argv[1]);
    execute_system_command(argv[1]);
    database_query(argv[1]);
    weak_hashing(argv[1]);
    
    return 0;
}
