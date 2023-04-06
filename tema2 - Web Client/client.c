#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include <stdbool.h>

#define MAX_COMMAND_SIZE 1024
#define HOST_SIZE 32

bool check_id(char *id)
{
    // check if the id has any space characters
    if (strchr(id, ' ') != NULL ) {
        return false;
    }

    return true;
}

bool check_user_and_pass(char *user, char *pass)
{
    // check if the user and pass have any space characters
    if (strchr(user, ' ') != NULL || strchr(pass, ' ') != NULL) {
        return false;
    }

    return true;
}

void register_user(int port_no, char *host, char *url, char *content_type)
{   
    char username[MAX_COMMAND_SIZE], password[MAX_COMMAND_SIZE];

    printf("username=");
    fgets(username, MAX_COMMAND_SIZE, stdin);
    username[strcspn(username, "\n")] = '\0';

    printf("password=");
    fgets(password, MAX_COMMAND_SIZE, stdin);
    password[strcspn(password, "\n")] = '\0';

    // check if the username and password are valid
    if (check_user_and_pass(username, password) == true) {
        // if they are, send the request to the server
        int sockfd = open_connection(host, port_no, AF_INET, SOCK_STREAM, 0);
        char **body_data = calloc(2, sizeof(char *));
        char *message, *response;

        body_data[0] = calloc(100, sizeof(char));
        body_data[1] = calloc(100, sizeof(char));
        sprintf(body_data[0], "\"username\": \"%s\"", username);
        sprintf(body_data[1], "\"password\": \"%s\"", password);

        message = compute_post_request(host, url, content_type, body_data, 2, NULL, 0, NULL);
        // send the message    
        send_to_server(sockfd, message);

        response = receive_from_server(sockfd);

        // if the response contains an error, print it
        if (strstr(response, "error") != NULL) {
            char *error_start, *error_end, *error;

            error_start = strstr(response, "error") + 8;

            error_end = strstr(error_start, "\"}");
            *error_end = '\0';
            
            error = calloc(200, sizeof(char));
            strncpy(error, error_start, error_end - error_start);
            printf("Error: %s\n", error);
        } else {
            printf("Successfully registered!\n");
        }

        close_connection(sockfd);
    } else {
        // if the username and password are not valid, print an error message
        printf("Invalid username or password format\n");
    }
}

char * login_user(bool *is_logged_in, int port_no, char *host, char *url, char *content_type)
{   
    char username[MAX_COMMAND_SIZE], password[MAX_COMMAND_SIZE];

    printf("username=");
    fgets(username, MAX_COMMAND_SIZE, stdin);
    username[strcspn(username, "\n")] = '\0';

    printf("password=");
    fgets(password, MAX_COMMAND_SIZE, stdin);
    password[strcspn(password, "\n")] = '\0';

    int sockfd = open_connection(host, port_no, AF_INET, SOCK_STREAM, 0);
    char *message, *response;
    char **body_data = calloc(2, sizeof(char *));

    body_data[0] = calloc(100, sizeof(char));
    body_data[1] = calloc(100, sizeof(char));
    sprintf(body_data[0], "\"username\": \"%s\"", username);
    sprintf(body_data[1], "\"password\": \"%s\"", password);

    message = compute_post_request(host, url, content_type, body_data, 2, NULL, 0, NULL);
    // send the message
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    close_connection(sockfd);

    // check if the response is valid
    if (strstr(response, "error") != NULL) {
        char *error_start, *error_end, *error;

        error_start = strstr(response, "error") + 8;

        error_end = strstr(error_start, "\"}");
        *error_end = '\0';

        error = calloc(200, sizeof(char));
        strncpy(error, error_start, error_end - error_start);
        printf("Error: %s\n", error);
        return NULL;
    } else {
        // extract the cookie from the response
        char *cookie_start, *cookie_end, *cookie;

        cookie_start = strstr(response, "connect.sid");

        cookie_end = strstr(cookie_start, ";");
        cookie = calloc(300, sizeof(char));

        strncpy(cookie, cookie_start, cookie_end - cookie_start);

        *is_logged_in = true;
        printf("Login successful\n");

        return cookie;
    }
}

char *enter_library(int port_no, char *host, char *url, char **cokies, int cookies_count, bool *jwt_is_set)
{
    int sockfd = open_connection(host, port_no, AF_INET, SOCK_STREAM, 0);
    char *message, *response;

    message = compute_get_request(host, url, NULL, cokies, cookies_count, NULL);
    // send the message
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);
    
    close_connection(sockfd);

    // if the response contains an error, print it
    if (strstr(response, "error") != NULL) {
        char *error_start, *error_end, *error;

        error_start = strstr(response, "error") + 8;

        error_end = strstr(error_start, "\"}");
        *error_end = '\0';
        
        error = calloc(200, sizeof(char));
        strncpy(error, error_start, error_end - error_start);
        printf("Error: %s\n", error);
        return NULL;
    } else {
        // extract the jwt token from the response
        char *token_end, *token_start, *token;

        token_end = strstr(response, "\"}");
        *(token_end) = '\0';

        token_start = strstr(response, "{\"token\":");
        token_start += 10;

        token = calloc(300, sizeof(char));
        strncpy(token, token_start, 300);

        *jwt_is_set = true;
        printf("Successfully entered the library\n");
        return token;
    }
}

void get_books(int port_no, char *host, char *url, char **cokies, int cookies_count, char *jwt)
{
    int sockfd = open_connection(host, port_no, AF_INET, SOCK_STREAM, 0);
    char *message, *response;

    message = compute_get_request(host, url, NULL, cokies, cookies_count, jwt);
    // send the message
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    close_connection(sockfd);
    
    // if the response contains an error, print it
    if (strstr(response, "error") != NULL) {
        char *error_start, *error_end, *error;

        error_start = strstr(response, "error") + 8;

        error_end = strstr(error_start, "\"}");
        *error_end = '\0';
        
        error = calloc(200, sizeof(char));
        strncpy(error, error_start, error_end - error_start);
        printf("Error: %s\n", error);
    } else {
        // extract the books from the response
        char *books_start, *books_end, *books;
        
        books_start= strstr(response, "[");
        
        books_end = strstr(response, "]");
        books_end += 1;
        *books_end = '\0';
        
        books = calloc(1024, sizeof(char));
        strncpy(books, books_start, books_end - books_start);
        printf("Successfully got the books\n");
        printf("Books: %s\n", books);
    }
}

void get_book(int port_no, char *host, char *url, char **cokies, int cookies_count, char *jwt)
{
    int sockfd = open_connection(host, port_no, AF_INET, SOCK_STREAM, 0);
    char *message, *response;

    message = compute_get_request(host, url, NULL, cokies, cookies_count, jwt);
    // send the message
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    close_connection(sockfd);
    
    // if the response contains an error, print it
    if (strstr(response, "error") != NULL) {
        char *error_start, *error_end, *error;

        error_start = strstr(response, "error") + 8;

        error_end = strstr(error_start, "\"}");
        *error_end = '\0';
        
        error = calloc(200, sizeof(char));
        strncpy(error, error_start, error_end - error_start);
        printf("Error: %s\n", error);
    } else {
        // extract the books from the response
        char *books_start, *books_end, *books;
        
        books_start= strstr(response, "[");
        
        books_end = strstr(response, "]");
        books_end += 1;
        *books_end = '\0';
        
        books = calloc(1024, sizeof(char));
        strncpy(books, books_start, books_end - books_start);
        printf("Successfully got the requested book\n");
        printf("Book: %s\n", books);
    }
}

bool check_book(char *title, char *author, char *genre, char *page_count, char *publisher)
{
    char numbers[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    // check if the author or genre contains numbers
    for (int i = 0; i < 10; i++) {
        if (strchr(author, numbers[i]) != NULL) {
            return false;
        }
        if (strchr(genre, numbers[i]) != NULL) {
            return false;
        }
    }

    return true;
}

void add_book(int port_no, char *host, char *url, char **cookies, int cookies_count, char *jwt)
{
    char title[MAX_COMMAND_SIZE];
    char author[MAX_COMMAND_SIZE];
    char genre[MAX_COMMAND_SIZE];
    char page_count[MAX_COMMAND_SIZE];
    char publisher[MAX_COMMAND_SIZE];

    printf("title=");
    fgets(title, MAX_COMMAND_SIZE, stdin);
    title[strcspn(title, "\n")] = 0;

    printf("author=");
    fgets(author, MAX_COMMAND_SIZE, stdin);
    author[strcspn(author, "\n")] = 0;

    printf("genre=");
    fgets(genre, MAX_COMMAND_SIZE, stdin);
    genre[strcspn(genre, "\n")] = 0;

    printf("page_count=");
    fgets(page_count, MAX_COMMAND_SIZE, stdin);
    page_count[strcspn(page_count, "\n")] = 0;

    printf("publisher=");
    fgets(publisher, MAX_COMMAND_SIZE, stdin);
    publisher[strcspn(publisher, "\n")] = 0;

    if (check_book(title, author, genre, page_count, publisher) == false) {
        printf("Error: Invalid book format\n");
    } else {
        char **body_data = calloc(5, sizeof(char *));
        for (int i = 0; i < 5; i++) {
            body_data[i] = calloc(100, sizeof(char));
        }

        sprintf(body_data[0], "\"title\": \"%s\"", title);
        sprintf(body_data[1], "\"author\": \"%s\"", author);
        sprintf(body_data[2], "\"genre\": \"%s\"", genre);
        sprintf(body_data[3], "\"page_count\": %s", page_count);
        sprintf(body_data[4], "\"publisher\": \"%s\"", publisher);

        char *message, *response;
        int sockfd = open_connection(host, port_no, AF_INET, SOCK_STREAM, 0);

        message = compute_post_request(host, url, "application/json", body_data, 5, cookies, cookies_count, jwt);
        // send the message 
        send_to_server(sockfd, message);
        response = receive_from_server(sockfd);

        close_connection(sockfd);

        // if the response contains an error, print it
        if (strstr(response, "error") != NULL) {
            char *error_start, *error_end, *error;

            error_start = strstr(response, "error") + 8;

            error_end = strstr(error_start, "\"}");
            *error_end = '\0';
            
            error = calloc(200, sizeof(char));
            strncpy(error, error_start, error_end - error_start);
            printf("Error: %s\n", error);
        } else {
            printf("Successfully added the book\n");
        }
    }
}

void delete_book(int port_no, char *host, char *url, char **cookies, int cookies_count, char *jwt)
{
    int sockfd = open_connection(host, port_no, AF_INET, SOCK_STREAM, 0);
    char *message, *response;

    message = compute_delete_request(host, url, NULL, cookies, cookies_count, jwt);
    // send the message
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    close_connection(sockfd);

    // if the response contains an error, print it
    if (strstr(response, "error") != NULL) {
        char *error_start, *error_end, *error;

        error_start = strstr(response, "error") + 8;

        error_end = strstr(error_start, "\"}");
        *error_end = '\0';
        
        error = calloc(200, sizeof(char));
        strncpy(error, error_start, error_end - error_start);
        printf("Error: %s\n", error);
    } else {
        printf("Successfully deleted the book\n");
    }
}

void logout_user(int port_no, char *host, char *url, char **cookies, int cookies_count, char *jwt)
{
    int sockfd = open_connection(host, port_no, AF_INET, SOCK_STREAM, 0);
    char *message, *response; 
    
    message = compute_get_request(host, url, NULL, cookies, cookies_count, jwt);
    // send the message
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    close_connection(sockfd);

    // if the response contains an error, print it
    if (strstr(response, "error") != NULL) {
        char *error_start, *error_end, *error;

        error_start = strstr(response, "error") + 8;

        error_end = strstr(error_start, "\"}");
        *error_end = '\0';
        
        error = calloc(200, sizeof(char));
        strncpy(error, error_start, error_end - error_start);
        printf("Error: %s\n", error);
    } else {
        printf("Successfully logged out\n");
    }
}

int main(int argc, char *argv[])
{
    char host[HOST_SIZE] = "34.241.4.235";
    char **cookies = calloc(10, sizeof(char *));
    char *jwt = NULL;
    int port_no = 8080;
    bool is_logged_in = false;
    bool jwt_is_set = false;

    while(1) {
        char command[MAX_COMMAND_SIZE];
        fgets(command, MAX_COMMAND_SIZE, stdin);
        command[strcspn(command, "\n")] = 0;

        if(!strcmp(command, "register")) {
            if (is_logged_in == true) {
                printf("Log out before registering another account!\n");
            } else {
                register_user(port_no, host, "/api/v1/tema/auth/register", "application/json");
            }
        } else if(!strcmp(command, "login")) {
            if (is_logged_in == true) {
                printf("You are already logged in\n");
            } else {
                cookies[0] = login_user(&is_logged_in, port_no, host, "/api/v1/tema/auth/login", "application/json");
            }
        } else if(!strcmp(command, "enter_library")) {
            if (is_logged_in == false) {
                printf("You must be logged in to enter the library\n");
            } else if (jwt_is_set == true) {
                printf("You are already in the library\n");
            } else {
                jwt = enter_library(port_no, host, "/api/v1/tema/library/access", cookies, 1, &jwt_is_set);
            }
        } else if(!strcmp(command, "get_books")) {
            if (is_logged_in == false) {
                printf("You must be logged in to get books\n");
            }
            else if (jwt_is_set == false) {
                printf("You must enter the library to get books\n");
            } else {
                get_books(port_no, host, "/api/v1/tema/library/books", cookies, 1, jwt);
            }
        } else if(!strcmp(command, "get_book")) {
            char book_id[MAX_COMMAND_SIZE];
            printf("id=");
            fgets(book_id, MAX_COMMAND_SIZE, stdin);
            book_id[strcspn(book_id, "\n")] = 0;

            if (check_id(book_id) == false) {
                printf("Invalid id\n");
                continue;
            }

            if (is_logged_in == false) {
                printf("You must be logged in to get the book\n");
            }
            else if (jwt_is_set == false) {
                printf("You must enter the library to get the book\n");
            } else {
                char *url = calloc(200, sizeof(char));
                sprintf(url, "/api/v1/tema/library/books/%s", book_id);

                get_book(port_no, host, url, cookies, 1, jwt);
            }
        } else if(!strcmp(command, "add_book")) {
            if (is_logged_in == false) {
                printf("You must be logged in to get the book\n");
            }
            else if (jwt_is_set == false) {
                printf("You must enter the library to get the book\n");
            } else {
                add_book(port_no, host, "/api/v1/tema/library/books", cookies, 1, jwt);
            }
        } else if(!strcmp(command, "delete_book")) {
            char book_id[MAX_COMMAND_SIZE];
            printf("id=");
            fgets(book_id, MAX_COMMAND_SIZE, stdin);
            book_id[strcspn(book_id, "\n")] = 0;

            if (check_id(book_id) == false) {
                printf("Invalid id\n");
                continue;
            }
            
            if (is_logged_in == false) {
                printf("You must be logged in to delete the book\n");
            }
            else if (jwt_is_set == false) {
                printf("You must enter the library to get the book\n");
            } else {
                char *url = calloc(200, sizeof(char));
                sprintf(url, "/api/v1/tema/library/books/%s", book_id);
                delete_book(port_no, host, url, cookies, 1, jwt);
            }
        } else if(!strcmp(command, "logout")) {
            if (is_logged_in == false) {
                printf("You must be logged in to logout\n");
            } else {
                logout_user(port_no, host, "/api/v1/tema/auth/logout", cookies, 1, jwt);
                is_logged_in = false;
                jwt_is_set = false;
            }
        } else if(!strcmp(command, "exit")) {
            exit(0);
        } else {
            printf("Invalid command\n");
        }
    }    
    
    return 0;
}
