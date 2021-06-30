//
// Created by Dominik on 28. 9. 2020.
//
//define because getline does not work otherwise
#define _GNU_SOURCE
#include "kube-fileparser.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int parse_line(const char *line, size_t length, char *key, char *value) {
	if(length > 255) {
		//line is too long
		return -1;
	}
	char *delim_ptr = strstr(line, "=");
	if(!delim_ptr) {
		//not valid line
		return -1;
	}
	char *end_ptr = strstr(delim_ptr, "\n");
	if(!end_ptr) {
		//not valid line
		return -1;
	}
	strncpy(key, line, delim_ptr - line);
	key[delim_ptr - line] = '\0';
	strncpy(value, delim_ptr + 1, end_ptr - delim_ptr - 1);
	value[end_ptr - delim_ptr - 1] = '\0';
	return 0;
}

int find_attribute(const char *filename, const char *key, char *value, const uint8_t max_length) {
	FILE *f = fopen(filename, "r");
	if (f == NULL) {
		//file cannot be opened
		return -1;
	}
	char left[128];
	char right[128];
	char *delim_ptr;
	char *end_ptr;
	char *line;
	size_t len = 0;
	while(getline(&line, &len, f) != -1) {
		if (parse_line(line, len, left, right)) {
			continue;
		}
		if (strcmp(key, left) == 0) {
			//key found
			strcpy(value, right);
			printf("value is: %s\n", value);
			return strlen(right);
		}
		line = NULL;
	}
	fclose(f);
	free(line);
	//key not found in whole file
	return 0;
}

int find_attributes(const char *filename, const char **keys, char **values, const uint8_t count, const uint8_t max_length) {
	FILE *f = fopen(filename, "r");
	if (f == NULL) {
		//file cannot be opened
		return -1;
	}
	char left[128];
	char right[128];
	char *delim_ptr;
	char *end_ptr;
	char *line;
	size_t len = 0;
	int found_keys = 0;
	while (1) {
		//when while condition was "getline(getline(&line, &len, f) != -1" program failed with SIGABRT
		//so I decided to assisgn result to variable and compare it to -1
		size_t res = getline(&line, &len, f);
		if (res == -1) {
			break;
		}
		if (parse_line(line, len, left, right)) {
			continue;
		}
		for (uint8_t i = 0; i < count; i++) {
			if (strcmp(keys[i], left) == 0) {
				strcpy(values[i], right);
				found_keys++;
				break;
			}
		}
		line = NULL;
	}
	fclose(f);
	free(line);
	return found_keys;
}
