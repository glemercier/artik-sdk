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


#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "artik_log.h"
#include "artik_pwm.h"
#include "os_pwm.h"

#include <tinyara/pwm.h>

#define MAX_SIZE	32

artik_error os_pwm_request(artik_pwm_config *config)
{
#ifdef CONFIG_PWM
	int fd;
	char devname[MAX_SIZE];

	snprintf(devname, MAX_SIZE, "/dev/pwm%d", config->pin_num);
	fd = open(devname, O_RDWR);
	if (fd < 0) {
		log_err("Failed to open %s (%d)", devname, errno);
		return E_ACCESS_DENIED;
	}
	config->user_data = (void *)fd;

	return S_OK;
#else
	return E_NOT_SUPPORTED;
#endif
}

artik_error os_pwm_release(artik_pwm_config *config)
{
#ifdef CONFIG_PWM
	artik_error res = S_OK;

	res = os_pwm_enable(config, false);
	close((int)config->user_data);
	config->user_data = NULL;

	return res;
#else
	return E_NOT_SUPPORTED;
#endif
}

artik_error os_pwm_enable(artik_pwm_config *config, bool state)
{
#ifdef CONFIG_PWM
	int ret = 0;

	ret = ioctl((int) config->user_data, state ? PWMIOC_START : PWMIOC_STOP, 0);

	if (ret < 0) {
		log_err("Failed to %s PWM (err=%d)", state ? "enable" : "disable", ret);
		return E_ACCESS_DENIED;
	}

	return S_OK;
#else
	return E_NOT_SUPPORTED;
#endif
}

artik_error os_pwm_set_period(artik_pwm_config *config, unsigned int value)
{
#ifdef CONFIG_PWM
	struct pwm_info_s *info = NULL;

	if (ioctl((int)config->user_data, PWMIOC_GETCHARACTERISTICS,
					(unsigned long)((uintptr_t)info)) < 0)
		return E_ACCESS_DENIED;

	info->frequency = value;

	if (ioctl((int)config->user_data, PWMIOC_SETCHARACTERISTICS,
					(unsigned long)((uintptr_t)info)) < 0)
		return E_ACCESS_DENIED;

	return S_OK;
#else
	return E_NOT_SUPPORTED;
#endif
}

artik_error os_pwm_set_polarity(artik_pwm_config *config,
		artik_pwm_polarity_t value)
{
	return E_NOT_SUPPORTED;
}

artik_error os_pwm_set_duty_cycle(artik_pwm_config *config, unsigned int value)
{
#ifdef CONFIG_PWM
	struct pwm_info_s *info = NULL;

	if (ioctl((int)config->user_data, PWMIOC_GETCHARACTERISTICS,
					(unsigned long)((uintptr_t)info)) < 0)
		return E_ACCESS_DENIED;

	info->duty = value * 65536 / 100;

	if (ioctl((int)config->user_data, PWMIOC_SETCHARACTERISTICS,
					(unsigned long)((uintptr_t)info)) < 0)
		return E_ACCESS_DENIED;

	return S_OK;
#else
	return E_NOT_SUPPORTED;
#endif
}
