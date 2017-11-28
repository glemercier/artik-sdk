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

#include <artik_log.h>

#include "artik_pwm.h"
#include "os_pwm.h"

typedef struct {
	int	*fd;
	int	chip;
	int	port;

} artik_pwm_user_data_t;

typedef enum {
	ARTIK_PWM_EXP = 0,
	ARTIK_PWM_UEXP,
	ARTIK_PWM_ENB,
	ARTIK_PWM_CYCL,
	ARTIK_PWM_PERD,
	ARTIK_PWM_POLR
} artik_pwm_path_index_t;

static char *const tab_value_polarity[] = { "normal", "inversed" };

/*
 * tab_value_path is linked to the enum artik_pwm_path_index_t.
 * each enum value match to each entry order of the table.
 */
static char *const tab_value_path[] = {
	"/sys/class/pwm/pwmchip%d/export",
	"/sys/class/pwm/pwmchip%d/unexport",
	"/sys/class/pwm/pwmchip%d/pwm%d/enable",
	"/sys/class/pwm/pwmchip%d/pwm%d/duty_cycle",
	"/sys/class/pwm/pwmchip%d/pwm%d/period",
	"/sys/class/pwm/pwmchip%d/pwm%d/polarity"
};

#define TAB_SIZE(x) (sizeof(x)/sizeof(*x))

#define MAX_SIZE	128

static char *itoa(int n, char *s)
{
	snprintf(s, 17, "%d", n);
	return s;
}

static artik_error os_pwm_ioctl(artik_pwm_user_data_t *user_data,
				artik_pwm_path_index_t ifd, char *value)
{
	artik_error res = S_OK;
	int ret;

	ret = write(user_data->fd[ifd], value, (ifd == ARTIK_PWM_ENB ?
						1 : strlen(value)));

	if (ret < 0) {
		log_err("%s write : %s", __func__, strerror(errno));

		switch (errno) {
		case EINVAL:
			res = E_INVALID_VALUE;
			break;
		case EBADF:
			res = E_BAD_ARGS;
			break;
		case EDESTADDRREQ:
			res = E_NOT_INITIALIZED;
			break;
		case EAGAIN:
			res = E_TRY_AGAIN;
			break;
		case EFBIG:
			res = E_OVERFLOW;
			break;
		case EINTR:
		case EPIPE:
			res = E_INTERRUPTED;
			break;
		case EIO:
			res = E_BUSY;
			break;
		default:
			res = E_NO_MEM;
			break;
		}

	}

	return (res >= S_OK) ? S_OK : res;
}

static int os_pwm_open(artik_pwm_user_data_t *user_data,
						artik_pwm_path_index_t ifd)
{
	char tmp_str[MAX_SIZE];

	log_dbg("");

	if (ifd != ARTIK_PWM_UEXP)
		snprintf(tmp_str, MAX_SIZE, tab_value_path[ifd],
				user_data->chip, user_data->port);
	else
		snprintf(tmp_str, MAX_SIZE, tab_value_path[ifd],
				user_data->chip);
	user_data->fd[ifd] = open(tmp_str, O_SYNC | O_WRONLY);
	return user_data->fd[ifd];
}

static artik_error os_pwm_uexport(artik_pwm_user_data_t *user_data,
						artik_pwm_path_index_t ifd)
{
	artik_error res = S_OK;
	char port[17];

	log_dbg("");

	if (os_pwm_open(user_data, ifd) < 0)
		return E_BUSY;

	res = os_pwm_ioctl(user_data, ifd, itoa(user_data->port, port));
	if (res != S_OK)
		goto exit;

exit:
	close(user_data->fd[ifd]);
	user_data->fd[ifd] = -1;
	return res;
}


static artik_error os_pwm_init(artik_pwm_config *config,
					artik_pwm_user_data_t *user_data)
{
	artik_error ret = S_OK;
	int len = TAB_SIZE(tab_value_path);
	int i = ARTIK_PWM_ENB;

	log_dbg("");

	config->user_data = malloc(sizeof(artik_pwm_user_data_t));
	user_data = config->user_data;
	user_data->fd = malloc(sizeof(*user_data->fd) * len);
	user_data->port = config->pin_num;
	user_data->chip = user_data->port & 0xff00;
	user_data->chip >>= 8;
	user_data->chip &= 0xff;
	user_data->port &= 0xff;
	ret = os_pwm_uexport(user_data, ARTIK_PWM_EXP);
	if (ret != S_OK)
		goto exit;

	while (i < len) {
		if (os_pwm_open(user_data, i) < 0) {
			ret = E_BAD_ARGS;
			goto exit;
		}
		++i;
	}

exit:
	if (ret != S_OK) {
		free(user_data->fd);
		free(user_data);
		config->user_data = NULL;
	}

	return ret;
}

static artik_error os_pwm_clean(artik_pwm_user_data_t *user_data)
{
	int len = TAB_SIZE(tab_value_path);
	int i = ARTIK_PWM_ENB;

	log_dbg("");

	if (user_data) {
		if (user_data->fd) {
			while (i < len) {
				if (user_data->fd[i] != -1)
					close(user_data->fd[i]);
				++i;
			}
			free(user_data->fd);
		}
		free(user_data);
	}
	return S_OK;
}


artik_error os_pwm_request(artik_pwm_config *config)
{
	artik_pwm_user_data_t *user_data = NULL;
	artik_error res = S_OK;

	log_dbg("");

	if (config->duty_cycle == 0)
		config->duty_cycle = config->period / 2;

	res = os_pwm_init(config, user_data);
	if (res != S_OK)
		return res;

	res = os_pwm_enable(config, true);
	if (res != S_OK)
		goto exit;

	res = os_pwm_set_polarity(config, config->polarity);
	if (res != S_OK)
		goto exit;

	res = os_pwm_set_period(config, config->period);
	if (res != S_OK)
		goto exit;

	res = os_pwm_set_duty_cycle(config, config->duty_cycle);
	if (res != S_OK)
		goto exit;

exit:
	if (res != S_OK)
		os_pwm_release(config);

	return res;
}

artik_error os_pwm_release(artik_pwm_config *config)
{
	artik_error res = S_OK;

	log_dbg("");

	res = os_pwm_set_duty_cycle(config, 0);
	if (res != S_OK)
		goto exit;

	res = os_pwm_enable(config, false);
	if (res != S_OK)
		goto exit;

	res = os_pwm_uexport(config->user_data, ARTIK_PWM_UEXP);
	if (res != S_OK)
		goto exit;

	res = os_pwm_clean(config->user_data);
	if (res != S_OK)
		goto exit;

exit:
	return res;
}

artik_error os_pwm_enable(artik_pwm_config *config, bool state)
{
	char value;

	log_dbg("");

	value = state ? '1' : '0';

	return os_pwm_ioctl(config->user_data, ARTIK_PWM_ENB, &value);
}

artik_error os_pwm_set_period(artik_pwm_config *config, unsigned int value)
{
	artik_error res = S_OK;
	char val[17];

	log_dbg("");

	res = os_pwm_enable(config, false);
	if (res != S_OK)
		goto exit;

	res = os_pwm_ioctl(config->user_data, ARTIK_PWM_PERD, itoa(value, val));
	if (res != S_OK)
		goto exit;

	res = os_pwm_enable(config, true);
	if (res != S_OK)
		goto exit;

exit:
	return res;
}

artik_error os_pwm_set_polarity(artik_pwm_config *config,
				artik_pwm_polarity_t value)
{
	artik_error res = S_OK;

	log_dbg("");

	if ((value != ARTIK_PWM_POLR_NORMAL) && (value != ARTIK_PWM_POLR_INVERT))
		return E_BAD_ARGS;

	res = os_pwm_enable(config, false);
	if (res != S_OK)
		goto exit;

	res = os_pwm_ioctl(config->user_data, ARTIK_PWM_POLR,
			tab_value_polarity[value]);
	if (res != S_OK)
		goto exit;

	res = os_pwm_enable(config, true);
	if (res != S_OK)
		goto exit;

exit:
	return res;
}

artik_error os_pwm_set_duty_cycle(artik_pwm_config *config, unsigned int value)
{
	artik_error res = S_OK;
	char val[17];

	log_dbg("");

	res = os_pwm_enable(config, false);
	if (res != S_OK)
		goto exit;

	res = os_pwm_ioctl(config->user_data, ARTIK_PWM_CYCL, itoa(value, val));
	if (res != S_OK)
		goto exit;

	res = os_pwm_enable(config, true);
	if (res != S_OK)
		goto exit;

exit:
	return res;
}
