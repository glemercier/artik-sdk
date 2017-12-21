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

#include <artik_gpio.h>
#include <artik_log.h>
#include "os_gpio.h"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <limits.h>
#include <sys/select.h>

#include <tinyara/fs/ioctl.h>

/*
 * Redefine struct/ioctl/enum from tinyara/gpio.h here since we cannot include
 * it due to namespace conflict on the direction configuration structure.
 * This should be taken care of in the next API-breaking release.
 */
#define GPIO_DIRECTION_OUT     1
#define GPIO_DIRECTION_IN      2
#define GPIO_DRIVE_PULLUP      1
#define GPIO_DRIVE_PULLDOWN    2
#define GPIO_CMD_SET_DIRECTION _GPIOIOC(0x0001)
#define GPIOIOC_POLLEVENTS     _GPIOIOC(0x0003)
#define GPIO_STACK_SIZE        2048
#define GPIO_SCHED_PRI         100
#define GPIO_SCHED_POLICY      SCHED_RR

struct gpio_pollevents_s {
	bool gp_rising;
	bool gp_falling;
};

typedef struct {
	int watch_id;
	int fd;
	fd_set rdfs;
	artik_gpio_callback callback;
	void *user_data;
	pthread_t thread_id;
	bool quit;
	artik_gpio_id id;
} os_gpio_data;

artik_error os_gpio_request(artik_gpio_config *config)
{
	os_gpio_data *user_data = NULL;

	user_data = malloc(sizeof(os_gpio_data));
	if (!user_data)
		return -E_NO_MEM;

	memset(user_data, 0, sizeof(os_gpio_data));
	config->user_data = user_data;

	char path_str[PATH_MAX];

	snprintf(path_str, PATH_MAX, "/dev/gpio%d", config->id);
	user_data->fd = open(path_str, O_RDWR);

	if (user_data->fd < 0) {
		os_gpio_release(config);
		return E_ACCESS_DENIED;
	}

	FD_ZERO(&user_data->rdfs);
	FD_SET(user_data->fd, &user_data->rdfs);

	user_data->id = config->id;

	return S_OK;
}

artik_error os_gpio_release(artik_gpio_config *config)
{
	os_gpio_data *user_data = config->user_data;

	close(user_data->fd);
	free(user_data);

	return S_OK;
}

int os_gpio_read(artik_gpio_config *config)
{
	os_gpio_data *user_data = config->user_data;
	char buf[4];

	if (ioctl(user_data->fd, GPIO_CMD_SET_DIRECTION, GPIO_DIRECTION_IN) < 0)
		return E_ACCESS_DENIED;

	if (read(user_data->fd, (void *)&buf, sizeof(buf)) < 0)
		return E_ACCESS_DENIED;

	return buf[0] == '1';
}

artik_error os_gpio_write(artik_gpio_config *config, int value)
{
	os_gpio_data *user_data = config->user_data;
	char str[4];

	if (ioctl(user_data->fd, GPIO_CMD_SET_DIRECTION,
		GPIO_DIRECTION_OUT) < 0)
		return E_ACCESS_DENIED;

	size_t str_size =  snprintf(str, 4, "%d", value != 0) + 1;

	if (write(user_data->fd, (void *)str, str_size) < 0)
		return E_ACCESS_DENIED;

	return S_OK;
}

static void *os_gpio_change_callback(void *user_data)
{
	os_gpio_data *data = (os_gpio_data *)user_data;
	struct pollfd poll_gpio;

	poll_gpio.fd = data->fd;
	poll_gpio.events = POLLPRI;

	while (!data->quit) {
		if (poll(&poll_gpio, 1, 100) >= 0) {
			if (poll_gpio.revents & POLLPRI) {
				char buf[4];

				if (lseek(poll_gpio.fd, 0, SEEK_SET) < 0)
					break;

				if (read(poll_gpio.fd, buf, sizeof(buf)) < 0)
					break;

				if (data->callback)
					data->callback(data->user_data, (buf[0] == '0') ? 0 : 1);
			}
		} else {
			break;
		}
	}

	pthread_exit(0);
}

artik_error os_gpio_set_change_callback(artik_gpio_config *config,
				artik_gpio_callback callback, void *user_data)
{
	os_gpio_data *data = (os_gpio_data *)config->user_data;
	struct gpio_pollevents_s pollevents;
	pthread_attr_t attr;
	int status, ret;
	struct sched_param sparam;
	char thread_name[16];

	if (data->callback)
		return E_BUSY;

	if (!callback)
		return E_BAD_ARGS;

	data->callback = callback;
	data->user_data = user_data;
	data->quit = false;

	/* Configure edge */
	switch (config->edge) {
	case GPIO_EDGE_RISING:
		pollevents.gp_rising  = true;
		pollevents.gp_falling = false;
		break;
	case GPIO_EDGE_FALLING:
		pollevents.gp_rising  = false;
		pollevents.gp_falling = true;
		break;
	case GPIO_EDGE_BOTH:
		pollevents.gp_rising  = true;
		pollevents.gp_falling = true;
		break;
	default:
		pollevents.gp_rising  = false;
		pollevents.gp_falling = false;
		break;
	}

	ret = ioctl(data->fd, GPIOIOC_POLLEVENTS, (unsigned long)&pollevents);
	if (ret) {
		log_err("Failed to configure interrupt edge\n");
		switch (errno) {
		case EPERM:
			return E_NOT_SUPPORTED;
		case EINVAL:
			return E_BAD_ARGS;
		default:
			return E_ACCESS_DENIED;
		}
	}

	status = pthread_attr_init(&attr);
	if (status != 0)
		return E_NOT_INITIALIZED;

	sparam.sched_priority = GPIO_SCHED_PRI;
	pthread_attr_setschedparam(&attr, &sparam);
	pthread_attr_setschedpolicy(&attr, GPIO_SCHED_POLICY);
	pthread_attr_setstacksize(&attr, GPIO_STACK_SIZE);
	status = pthread_create(&data->thread_id, &attr,
					os_gpio_change_callback, (void *)data);
	if (status < 0)
		return E_NOT_INITIALIZED;

	snprintf(thread_name, 16, "GPIO%d Watch", data->id);
	pthread_setname_np(data->thread_id, thread_name);

	return S_OK;
}

void os_gpio_unset_change_callback(artik_gpio_config *config)
{
	os_gpio_data *data = (os_gpio_data *)config->user_data;

	if (!data->callback)
		return;

	data->quit = true;
	pthread_join(data->thread_id, NULL);
	data->callback = NULL;
}
