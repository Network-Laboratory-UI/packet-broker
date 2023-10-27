// ======================================================= THE LIBRARY =======================================================

// C Library
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <curl/curl.h>
#include <time.h>
#include <unistd.h>

// ======================================================= THE DEFINE =======================================================

// Define constants
#define MAX_LINE_LENGTH 1024
#define CSV_FILE_PREFIX "stats"
#define CSV_FILE_EXTENSION ".csv"
#define MAX_FILES_TO_STORE 1000
#define MAX_FILE_NAME_LENGTH 128

// Time period in minutes to send data to the API
#define TIME_PERIOD_SEND 1

// Aggregator Statistics
struct aggregator_statistics_data
{
	int file_send;
    int data_send;
	int file_pending;
};
struct aggregator_statistics_data aggregator_statistics;

// PRINT OUT STATISTICS
static void
print_stats(void)
{
	const char clr[] = {27, '[', '2', 'J', '\0'};
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

	// Clear screen and move to top left
	printf("%s%s", clr, topLeft);
	printf("AGGREGATOR\n");
	printf("\nAggregator statistics ===========================");
    printf("\nStatistics for aggregator ----------------------");
    printf("\nFile sent    : %d",aggregator_statistics.file_send);
    printf("\ndata sent    : %d",aggregator_statistics.data_send);
    printf("\nFile Pending : %d",aggregator_statistics.file_pending);	
	fflush(stdout);
}

// Function to send data to the API
int sendToApi(json_t *jsonArray) {
    const char* apiUrl = "http://192.168.88.251:3000/npb/npb-packet";
    int status = 0; // Status to track if sending was successful

    CURL* curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize libcurl\n");
        return 1;
    }

    // Set the POST data and URL
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, apiUrl);

    // Convert the JSON array to a string
    char *jsonData = json_dumps(jsonArray, 0);

    if (jsonData) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData);
        // dont receive

        // Perform the POST request
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "Failed to send data to API: %s\n", curl_easy_strerror(res));
            status = 1; // Set status to indicate a failure
        }
        free(jsonData); // Free the allocated JSON data
    } else {
        fprintf(stderr, "Failed to create JSON data\n");
        status = 1; // Set status to indicate a failure
    }

    // Clean up
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return status;
}


// Function to process a CSV row and add it to the JSON array
void processCSVRow(const char* row, json_t *jsonArray) {
    char npb_id[16];
    char http_count[16];
    char https_count[16];
    char rx_count[16];
    char tx_count[16];
    char rx_size[16];
    char tx_size[16];
    char time[32];
    char throughput[16];

    sscanf(row, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^\n]", npb_id, http_count, https_count, rx_count, tx_count, rx_size, tx_size, time, throughput);

    // Create a JSON object for the row
    json_t *jsonRow = json_object();
    json_object_set_new(jsonRow, "npb_id", json_string(npb_id));
    json_object_set_new(jsonRow, "http_count", json_string(http_count));
    json_object_set_new(jsonRow, "https_count", json_string(https_count));
    json_object_set_new(jsonRow, "rx_count", json_string(rx_count));
    json_object_set_new(jsonRow, "tx_count", json_string(tx_count));
    json_object_set_new(jsonRow, "rx_size", json_string(rx_size));
    json_object_set_new(jsonRow, "tx_size", json_string(tx_size));
    json_object_set_new(jsonRow, "time", json_string(time));
    json_object_set_new(jsonRow, "throughput", json_string(throughput));

    // Add the JSON object to the array
    json_array_append_new(jsonArray, jsonRow);
}

// Function to construct the CSV file path based on the nearest past time
char* constructCSVFilePath(time_t currentTime) {
    char timeString[80];
    struct tm timeinfo;

    // Get the time string for the nearest past time
    int currentMinute = currentTime / 60;
    // Check if the current minute is divisible by TIME_PERIOD_SEND and it's a new minute.
    if (currentMinute % TIME_PERIOD_SEND == 0) {
        time_t intervalStartTime = currentTime - TIME_PERIOD_SEND * 60;
        intervalStartTime -= intervalStartTime % 60;

        strftime(timeString, sizeof(timeString), "%Y-%m-%dT%H:%M:%S", localtime_r(&intervalStartTime, &timeinfo));
    }

    // Construct the file path
    char* filePath = (char*)malloc(strlen("stats/") + strlen(CSV_FILE_PREFIX) + strlen(timeString) + strlen(CSV_FILE_EXTENSION) + 1);
    sprintf(filePath, "stats/%s%s%s", CSV_FILE_PREFIX, timeString, CSV_FILE_EXTENSION);
    return filePath;
}

int main() {
    int last_sent_minute = -1; // Initialize to an invalid value

    // Create an array to store filenames that failed to send
    char failedFiles[MAX_FILES_TO_STORE][MAX_FILE_NAME_LENGTH];
    int failedFileCount = 0;

    while (1) {
        time_t now;
        struct tm timeinfo;

        time(&now);
        localtime_r(&now, &timeinfo);

        int currentMinute = timeinfo.tm_min;

        // Check if the current minute is divisible by TIME_PERIOD_SEND and it's a new minute.
        if (currentMinute % TIME_PERIOD_SEND == 0 && currentMinute != last_sent_minute) {
            sleep(1); // Sleep for 1 second to make sure the CSV file is ready
            char* filePath = constructCSVFilePath(now);
            FILE* file = fopen(filePath, "r");

            print_stats();

            printf("\nReading file: %s\n", filePath);

            // Resend failed files
            for (int i = 0; i < failedFileCount; i++) {
                // Open the failed file
                char* failedFilePath = failedFiles[i];
                FILE* failedFile = fopen(failedFilePath, "r");

                if (!failedFile) {
                    perror("Error opening failed CSV file");
                } else {
                    char failedLine[MAX_LINE_LENGTH];

                    // Skip the header line
                    if (fgets(failedLine, sizeof(failedLine), failedFile) == NULL) {
                        perror("Error reading header line");
                        fclose(failedFile);
                    } else {
                        // Create a JSON array to store rows
                        json_t *failedJsonArray = json_array();
                        while (fgets(failedLine, sizeof(failedLine), failedFile) != NULL) {
                            processCSVRow(failedLine, failedJsonArray);
                        }
                        printf("Resending JSON array size: %ld\n", json_array_size(failedJsonArray));

                        // Send the JSON array to the API
                        if (json_array_size(failedJsonArray) > 0) {
                            int resendStatus = sendToApi(failedJsonArray);
                            if (resendStatus == 0) {
                                printf("Successfully resent data to API for file: %s\n", failedFilePath);
                                // Remove the resend file
                                if (remove(failedFilePath) != 0) {
                                    perror("Error removing resend file");
                                }
                                aggregator_statistics.data_send += json_array_size(failedJsonArray);
                                aggregator_statistics.file_send++;
                                aggregator_statistics.file_pending--;
                            } else {
                                printf("Failed to resend data to API for file: %s\n", failedFilePath);
                                // You can choose to add the file back to the failedFiles array here if needed
                            }
                        }
                        json_decref(failedJsonArray); // Cleanup the JSON array

                        fclose(failedFile);
                    }
                }
            }

            if (file) {
                char line[MAX_LINE_LENGTH];

                // Skip the header line
                if (fgets(line, sizeof(line), file) == NULL) {
                    perror("Error reading header line");
                    fclose(file);
                } else {
                    // Create a JSON array to store rows
                    json_t *jsonArray = json_array();
                    while (fgets(line, sizeof(line), file) != NULL) {
                        processCSVRow(line, jsonArray);
                    }
                    printf("Json array size: %ld\n", json_array_size(jsonArray));

                    // Send the JSON array to the API
                    if (json_array_size(jsonArray) > 0) {
                        int initialSendStatus = sendToApi(jsonArray);
                        if (initialSendStatus == 0) {
                            printf("Successfully sent data to API\n");
                            aggregator_statistics.data_send += json_array_size(jsonArray);
                            aggregator_statistics.file_send++;
                            sleep(1);
                            // Remove the file
                            if (remove(filePath) != 0) {
                                perror("Error removing file");
                            }
                        } else {
                            printf("Failed to send data to API\n");
                            // Store the filename in the failedFiles array
                            if (failedFileCount < MAX_FILES_TO_STORE) {
                                strncpy(failedFiles[failedFileCount], filePath, MAX_FILE_NAME_LENGTH);
                                failedFiles[failedFileCount][MAX_FILE_NAME_LENGTH - 1] = '\0'; // Null-terminate the copied string
                                printf("Failed to send file: %s\n", failedFiles[failedFileCount]);
                                aggregator_statistics.file_pending++;
                                failedFileCount++;
                            } else {
                                printf("Max failed files exceeded, some filenames may be lost.\n");
                            }
                        }
                    }
                    json_decref(jsonArray); // Cleanup the JSON array

                    fclose(file);
                }
            }
            print_stats();
            last_sent_minute = currentMinute; // Update the last sent minute
        }
    }
    return 0;
}
