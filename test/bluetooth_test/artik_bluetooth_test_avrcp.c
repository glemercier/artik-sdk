/*
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include <artik_module.h>
#include <artik_loop.h>
#include <artik_bluetooth.h>
#include "artik_bluetooth_test_commandline.h"

#define MAX_BUFFER_SIZE 1024

static artik_bluetooth_module *bt;
static artik_loop_module *loop;
static int g_quit;

static int index_to_int(char *index)
{
	const char *s = index;
	int result;

	printf("convert index[%s]\n", index);
	if (NULL == index || 0 == strlen(index)) {
		fprintf(stdout, "Index is NULL or empty.\n");
		return -1;
	}

	while (*s != '\0') {
		if (*s >= '0' && *s <= '9') {
			s++;
		} else {
			fprintf(stdout, "Please input correct index.\n");
			return -1;
		}
	}

	result = atoi(index);
	return result;
}

void print_devices(artik_bt_device *devices, int num)
{
	int i = 0, j = 0;

	for (i = 0; i < num; i++) {
		fprintf(stdout, "Address: %s\n",
			devices[i].remote_address ? devices[i].remote_address : "(null)");
		fprintf(stdout, "Name: %s\n",
			devices[i].remote_name ? devices[i].remote_name : "(null)");
		fprintf(stdout, "Bonded: %s\n",
			devices[i].is_bonded ? "true" : "false");
		fprintf(stdout, "Connected: %s\n",
			devices[i].is_connected ? "true" : "false");
		fprintf(stdout, "Authorized: %s\n",
			devices[i].is_authorized ? "true" : "false");
		if (devices[i].uuid_length > 0) {
			fprintf(stdout, "UUIDs:\n");
			for (j = 0; j < devices[i].uuid_length; j++) {
				fprintf(stdout, "\t%s [%s]\n",
					devices[i].uuid_list[j].uuid_name,
					devices[i].uuid_list[j].uuid);
			}
		}

		fprintf(stdout, "\n");
		fprintf(stdout, "Scaning......\n");
	}
}

void print_metadata(artik_bt_avrcp_track_metadata *metadata)
{
	if (metadata == NULL)
		return;
	printf("\t##Title: %s\t\t", metadata->title);
	printf("Artist: %s\n", metadata->artist);
	printf("\t##Album: %s\t\t", metadata->album);
	printf("Genre: %s\n", metadata->genre);
	printf("\t##Track #%d\t\t", metadata->number);
	printf("duration: %d ms\n", metadata->duration);
	printf("\t##Number of tracks: %d\n", metadata->number_of_tracks);
}

static void scan_callback(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_device *dev = (artik_bt_device *) data;

	print_devices(dev, 1);
}

static void on_timeout_callback(void *user_data)
{
	fprintf(stdout, "TEST: %s stop scanning, exiting loop\n", __func__);
	bt->stop_scan();
	bt->unset_callback(BT_EVENT_SCAN);

	loop->quit();
}

static void prv_start_scan(char *buffer, void *user_data)
{
	artik_error ret = S_OK;
	int timeout_id = 0;
	artik_bt_device *paired_device = NULL;
	int paired_device_num = 0;

	bt->get_devices(BT_DEVICE_PARIED, &paired_device, &paired_device_num);
	if (paired_device_num) {
		printf("\nPaired devices:\n");
		print_devices(paired_device, paired_device_num);
		bt->free_devices(&paired_device, paired_device_num);
	}

	ret = bt->set_callback(BT_EVENT_SCAN, scan_callback, "avrcp test");
	if (ret != S_OK) {
		printf("Set scan callback failed, Error[%d]\n", ret);
		return;
	}

	loop->add_timeout_callback(&timeout_id, 30000, on_timeout_callback,
				   NULL);

	printf("\nInvoke scan for 30 seconds...\n");
	ret = bt->start_scan();
	if (ret != S_OK)
		printf("Start scan failed\n");
	loop->run();
}

static void prv_connect(char *buffer, void *user_data)
{
	if (strlen(buffer) == 0) {
		printf("Please input device mac address you want to connect!\n");
		return;
	}
	artik_error error = S_OK;
	char *address = malloc(strlen(buffer));

	strncpy(address, buffer, strlen(buffer) - 1);
	address[strlen(buffer) - 1] = '\0';

	printf("Invoke connect to device [%s]...\n", address);
	error = bt->connect(address);
	if (error == S_OK)
		printf("Connect to device [%s] success\n", address);
	else
		printf("Connect to device [%s] failed\n", address);
	free(address);
}

static void prv_disconnect(char *buffer, void *user_data)
{
	if (strlen(buffer) == 0) {
		printf("\nPlease input device mac address you want to disconnect!\n");
		return;
	}
	artik_error error = S_OK;
	char *address = malloc(strlen(buffer));

	strncpy(address, buffer, strlen(buffer) - 1);
	address[strlen(buffer) - 1] = '\0';

	printf("Invoke disconnect to device [%s]...\n", address);
	error = bt->disconnect(address);
	if (error == S_OK)
		printf("Disconnect to device [%s] success\n", address);
	else
		printf("Disconnect to device [%s] failed\n", address);
	free(address);
}

static void prv_list_items(char *buffer, void *user_data)
{
	artik_error ret = S_OK;
	int start_item = -1;
	int end_item = -1;

	printf("Invoke list item...\n");

	if (strlen(buffer) > 0) {
		char *argv = NULL;
		char *arg = malloc(strlen(buffer));

		if (!arg)
			return;

		strncpy(arg, buffer, strlen(buffer) - 1);
		arg[strlen(buffer) - 1] = '\0';

		argv = strtok(arg, " ");
		start_item = strtol(argv, NULL, 10);
		argv = strtok(NULL, " ");
		end_item = strtol(argv, NULL, 10);
		if (arg)
			free(arg);
	}

	artik_bt_avrcp_item *item_list, *node;

	ret = bt->avrcp_controller_list_item(start_item, end_item, &item_list);
	if (ret == E_NOT_SUPPORTED) {
		printf("List item not supported !\n");
		return;
	}

	if (ret != S_OK) {
		printf("avrcp list item failed !\n");
		return;
	}

	node = item_list;

	while (node != NULL) {
		artik_bt_avrcp_item_property *property = node->property;

		if (property != NULL) {
			printf("\n#%d\t##Name: %s\t\t", node->index, property->name);
			printf("Type: %s\t\t", property->type);
			printf("Playable: %d\n", property->playable);
			if (strncmp(property->type, "folder", strlen("folder") + 1) == 0)
				printf("\t##Folder Type: %s\n", property->folder);
			else
				print_metadata(property->metadata);
		}
		node = node->next_item;
	}
}

static void prv_change_folder(char *buffer, void *user_data)
{
	if (strlen(buffer) == 0) {
		printf("Please input index of folder!\n");
		return;
	}

	artik_error ret = S_OK;
	char *index = malloc(strlen(buffer));
	int i = -1;

	if (!index)
		return;

	strncpy(index, buffer, strlen(buffer) - 1);
	index[strlen(buffer) - 1] = '\0';

	i = index_to_int(index);
	if (index)
		free(index);
	if (i >= 0) {
		printf("Invoke change folder...%d\n", i);
		ret = bt->avrcp_controller_change_folder(i);
		if (ret != S_OK)
			printf("avrcp change folder failed !\n");
	} else
		printf("Please Input valid parameter!\n");
}

static void prv_get_repeat_mode(char *buffer, void *user_data)
{
	artik_error ret = S_OK;
	artik_bt_avrcp_repeat_mode repeat_mode;

	ret = bt->avrcp_controller_get_repeat_mode(&repeat_mode);

	if (ret != S_OK) {
		printf("avrcp get repeat mode failed !\n");
		return;
	}

	if (repeat_mode == BT_AVRCP_REPEAT_SINGLETRACK)
		printf("Repeat mode is single\n");
	else if (repeat_mode == BT_AVRCP_REPEAT_ALLTRACKS)
		printf("Repeat mode is all\n");
	else if (repeat_mode == BT_AVRCP_REPEAT_GROUP)
		printf("Repeat mode is group\n");
	else if (repeat_mode == BT_AVRCP_REPEAT_OFF)
		printf("Repeat mode is off\n");
}

static void prv_set_repeat_mode(char *buffer, void *user_data)
{
	if (strlen(buffer) == 0) {
		printf("Please input repeat mode!\n");
		return;
	}

	artik_error ret = S_OK;
	int repeat;
	char *repeat_mode = malloc(strlen(buffer));

	if (!repeat_mode)
		return;

	strncpy(repeat_mode, buffer, strlen(buffer) - 1);
	repeat_mode[strlen(buffer) - 1] = '\0';
	if (strcmp(repeat_mode, "single") == 0) {
		repeat = 0;
	} else if (strcmp(repeat_mode, "all") == 0) {
		repeat = 1;
	} else if (strcmp(repeat_mode, "group") == 0) {
		repeat = 2;
	} else if (strcmp(repeat_mode, "off") == 0) {
		repeat = 3;
	} else {
		if (repeat_mode)
			free(repeat_mode);
		printf("invalid repeat mode\n");
		return;
	}

	if (repeat_mode)
		free(repeat_mode);

	ret = bt->avrcp_controller_set_repeat_mode(repeat);

	if (ret != S_OK)
		printf("avrcp set repeat mode failed !\n");
}

static void prv_play_item(char *buffer, void *user_data)
{
	if (strlen(buffer) == 0) {
		printf("Please input index of media item!\n");
		return;
	}

	artik_error ret = S_OK;
	char *index = malloc(strlen(buffer));
	int i = -1;

	if (!index)
		return;

	strncpy(index, buffer, strlen(buffer) - 1);
	index[strlen(buffer) - 1] = '\0';
	i = index_to_int(index);
	if (index)
		free(index);
	if (i > 0) {
		ret = bt->avrcp_controller_play_item(i);
		if (ret == E_NOT_SUPPORTED) {
			printf("Play this item not supported !\n");
			return;
		}
		if (ret != S_OK)
			printf("avrcp play_item failed !\n");
	} else
		printf("Please Input valid parameter!\n");
}

static void prv_add_to_playing(char *buffer, void *user_data)
{
	if (strlen(buffer) == 0) {
		printf("Please input index of media item!\n");
		return;
	}

	artik_error ret = S_OK;
	char *index = malloc(strlen(buffer));
	int i = -1;

	if (!index)
		return;

	strncpy(index, buffer, strlen(buffer) - 1);
	index[strlen(buffer) - 1] = '\0';
	i = index_to_int(index);
	if (index)
		free(index);
	if (i > 0) {
		printf("add to playing item:%d\n", i);
		ret = bt->avrcp_controller_add_to_playing(i);
		if (ret == E_NOT_SUPPORTED) {
			printf("Add this item to playing not supported !\n");
			return;
		}
		if (ret != S_OK)
			printf("avrcp add_to_playing failed !\n");
	} else
		printf("Please Input valid parameter!\n");
}

static void prv_resume_play(char *buffer, void *user_data)
{
	bt->avrcp_controller_resume_play();
}

static void prv_next(char *buffer, void *user_data)
{
	bt->avrcp_controller_next();
}

static void prv_previous(char *buffer, void *user_data)
{
	bt->avrcp_controller_previous();
}

static void prv_pause(char *buffer, void *user_data)
{
	bt->avrcp_controller_pause();
}

static void prv_stop(char *buffer, void *user_data)
{
	bt->avrcp_controller_stop();
}

static void prv_rewind(char *buffer, void *user_data)
{
	bt->avrcp_controller_rewind();
}

static void prv_fast_forward(char *buffer, void *user_data)
{
	bt->avrcp_controller_fast_forward();
}

static void prv_get_metadata(char *buffer, void *user_data)
{
	artik_error ret = S_OK;
	artik_bt_avrcp_track_metadata *m_metadata = NULL;

	ret = bt->avrcp_controller_get_metadata(&m_metadata);
	if (ret == S_OK && m_metadata) {
		print_metadata(m_metadata);
		ret = bt->avrcp_controller_free_metadata(&m_metadata);
	}
}

static void prv_quit(char *buffer, void *user_data)
{
	g_quit = 1;
	if (bt) {
		bt->deinit();
		artik_release_api_module(bt);
	}
	if (loop)
		artik_release_api_module(loop);
}

command_desc_t commands[] = {
		{"scan", "Start to scan bluetooth device around.", "scan",
			prv_start_scan, NULL},
		{"connect", "Connect to certain device address.",
			"connect 54:40:AD:E2:BE:35", prv_connect, NULL},
		{"disconnect", "Connect to certain device address.",
			"disconnect 54:40:AD:E2:BE:35", prv_disconnect, NULL},
		{"ls", "List item indexs of current folder.",
			"ls or ls 1 2", prv_list_items, NULL},
		{"cd", "Change to the specified index folder",
			"cd 1", prv_change_folder, NULL},
		{"get-repeat", "Get the repeat mode", "get-repeat",
			prv_get_repeat_mode, NULL},
		{"set-repeat", "Set the repeat mode",
			"set-repeat single/set-repeat all/set-repeat group/set-repeat off",
			prv_set_repeat_mode, NULL},
		{"play-item", "Play the specified index of item",
			"play-item 1",
			prv_play_item, NULL},
		{"addtoplay", "Add the specified index of item to playlist.",
			"addtoplay 1", prv_add_to_playing, NULL},
		{"resume-play", "Resume play.", "resume-play", prv_resume_play, NULL},
		{"next", "Play the next music.", "next", prv_next, NULL},
		{"previous", "Play the previous music.", "previous",
			prv_previous, NULL},
		{"pause", "Pause the playing music.", "pause", prv_pause, NULL},
		{"stop", "Stop playing music.", "stop", prv_stop, NULL},
		{"rewind", "Rewind the playing music.", "rewind", prv_rewind, NULL},
		{"fast-forward", "Fast-forward the playing music.", "fast-forward",
			prv_fast_forward, NULL},
		{"get-metadata", "Get the metadata of current controller.", "get-metadata",
			prv_get_metadata, NULL},
		{"quit", "Quit application.", "quit", prv_quit, NULL},

		COMMAND_END_LIST
};

int main(void)
{
	int i = 0;

	if (!artik_is_module_available(ARTIK_MODULE_BLUETOOTH)) {
		printf("TEST:Bluetooth module is not available, skipping test...\n");
		return -1;
	}

	bt = (artik_bluetooth_module *) artik_request_api_module("bluetooth");
	loop = (artik_loop_module *)artik_request_api_module("loop");

	bt->init();

	for (i = 0; commands[i].name != NULL; i++)
		printf("Command:[%s]\tDescription: %s\tExample: %s\n",
			commands[i].name,
			commands[i].short_desc,
			commands[i].long_desc);

	printf("\nPlease input command:\n");

	while (!g_quit) {
		fd_set readfds;
		int num_bytes;
		int result;
		char buffer[MAX_BUFFER_SIZE];
		struct timeval tv;

		tv.tv_sec = 60;
		tv.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(STDIN_FILENO, &readfds);
		result = select(FD_SETSIZE, &readfds, NULL, NULL, &tv);
		if (result < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "Error in select(): %d %s\r\n", errno,
						strerror(errno));
			}
		} else if (result > 0) {
			num_bytes = read(STDIN_FILENO, buffer, MAX_BUFFER_SIZE - 1);

			if (num_bytes > 1) {
				buffer[num_bytes] = 0;
				handle_command(commands, (char *) buffer);
			}
			if (g_quit == 0) {
				fprintf(stdout, "\r\n> ");
				fflush(stdout);
			} else {
				fprintf(stdout, "\r\n");
			}
		}

	}

	return 0;
}
