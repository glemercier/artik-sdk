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
#include <sys/time.h>
#include <sys/stat.h>

#include <artik_module.h>
#include <artik_cloud.h>

static char *token = NULL;
static char *device_id = NULL;
static char *user_id = NULL;
static char *app_id = NULL;
static char *message = NULL;
static char *action = NULL;
static char *device_type_id = NULL;
static char *data = NULL;
static bool timestamp = false;

static char *parse_json_object(const char *data, const char *obj)
{
	char *res = NULL;
	char prefix[256];
	char *substr = NULL;

	snprintf(prefix, 256, "\"%s\":\"", obj);

	substr = strstr(data, prefix);
	if (substr != NULL) {
		int idx = 0;

		/* Start after substring */
		substr += strlen(prefix);

		/* Count number of bytes to extract */
		while (substr[idx] != '\"')
			idx++;
		/* Copy the extracted string */
		res = strndup(substr, idx);
	}

	return res;
}

static artik_error test_get_user_profile(const char *t,
						artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->get_current_user_profile(t, &response, &ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	return ret;
}

static artik_error test_get_user_devices(const char *t, const char *uid,
						artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->get_user_devices(t, 100, false, 0, uid, &response,
								&ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(cloud);

	return ret;
}

static artik_error test_get_user_device_types(const char *t, const char *uid,
						artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->get_user_device_types(t, 100, false, 0, uid, &response,
								&ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(cloud);

	return ret;
}

static artik_error test_get_user_application_properties(const char *t,
						const char *uid,
						const char *aid,
						artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->get_user_application_properties(t, uid, aid, &response,
								&ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(cloud);

	return ret;
}

static artik_error test_get_device(const char *t, const char *did,
						artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->get_device(t, did, true, &response, &ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(cloud);

	return ret;
}

static artik_error test_get_device_token(const char *t, const char *did,
						artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->get_device_token(t, did, &response, &ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(cloud);

	return ret;
}

static artik_error test_cloud_message(const char *t, const char *did,
				const char *msg, artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->send_message(t, did, msg, &response, &ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(cloud);

	return ret;
}

static artik_error test_cloud_action(const char *t, const char *did,
				const char *act, artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->send_action(t, did, act, &response, &ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}
	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(cloud);

	return ret;
}

static artik_error test_update_device_token(const char *t, const char *did,
						artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->update_device_token(t, did, &response, &ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(cloud);

	return ret;
}

static artik_error test_delete_device_token(const char *t, const char *did,
						artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->delete_device_token(t, did, &response, &ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(cloud);

	return ret;
}

static artik_error test_add_delete_device(const char *t, const char *uid,
				const char *dtid, artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;
	char *device_id = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	/* Create a new device */
	ret = cloud->add_device(t, uid, dtid, "Test Device", &response,
								&ssl_config);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		goto exit;
	}

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
								response);
		device_id = parse_json_object(response, "id");
		free(response);
	} else {
		fprintf(stdout, "TEST: %s did not receive response\n",
								__func__);
		ret = E_BAD_ARGS;
		goto exit;
	}

	if (!device_id)	{
		fprintf(stdout, "TEST: %s failed to parse response\n",
								__func__);
		ret = E_BAD_ARGS;
		goto exit;
	}

	/* Check if the device has been created */
	ret = cloud->get_device(t, device_id, false, &response, &ssl_config);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		goto exit;
	}

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
								response);
		free(response);
	} else {
		fprintf(stdout, "TEST: %s did not receive response\n",
								__func__);
		ret = E_BAD_ARGS;
		goto exit;
	}

	/* Delete the device */
	ret = cloud->delete_device(t, device_id, &response, &ssl_config);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		goto exit;
	}

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
								response);
		free(response);
	} else {
		fprintf(stdout, "TEST: %s did not receive response\n",
								__func__);
		ret = E_BAD_ARGS;
		goto exit;
	}

exit:
	artik_release_api_module(cloud);

	fprintf(stdout, "TEST: %s %s\n", __func__, ret == S_OK ?
							"succeeded" : "failed");

	return ret;
}

static artik_error test_get_device_properties(const char *t, const char *uid,
					bool ts, artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->get_device_properties(t, uid, ts, &response, &ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(cloud);

	return ret;
}

static artik_error test_set_device_server_properties(const char *t,
					const char *uid, const char *d,
					artik_ssl_config ssl_config)
{
	artik_cloud_module *cloud = (artik_cloud_module *)
					artik_request_api_module("cloud");
	artik_error ret = S_OK;
	char *response = NULL;

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = cloud->set_device_server_properties(t, uid, d, &response,
								&ssl_config);

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
			response);
		free(response);
	}

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(cloud);

	return ret;
}

int main(int argc, char *argv[])
{
	artik_error ret = S_OK;
	artik_ssl_config ssl_config = {0};

	int opt;
	struct stat st;
	FILE *f;
	char *root_ca = NULL; // Root CA certificate

	if (!artik_is_module_available(ARTIK_MODULE_CLOUD)) {
		fprintf(stdout,
			"TEST: Cloud module is not available,"\
			" skipping test...\n");
		return -1;
	}

	while ((opt = getopt(argc, argv, "t:d:u:p:m:a:y:b:sr:v")) != -1) {
		switch (opt) {
		case 't':
			token = strndup(optarg, strlen(optarg));
			break;
		case 'd':
			device_id = strndup(optarg, strlen(optarg));
			break;
		case 'u':
			user_id = strndup(optarg, strlen(optarg));
			break;
		case 'p':
			app_id = strndup(optarg, strlen(optarg));
			break;
		case 'm':
			message = strndup(optarg, strlen(optarg));
			break;
		case 'a':
			action = strndup(optarg, strlen(optarg));
			break;
		case 'y':
			device_type_id = strndup(optarg, strlen(optarg));
			break;
		case 'b':
			data = strndup(optarg, strlen(optarg));
			break;
		case 's':
			timestamp = true;
			break;
		case 'v':
			ssl_config.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
			break;
		case 'r':
			f = fopen(optarg, "rb");
			if (!f) {
				printf("File not found for parameter -r\n");
				ret = E_BAD_ARGS;
				goto exit;
			}
			if (fstat(fileno(f), &st) < 0) {
				printf("Could not get file size\n");
				fclose(f);
				ret = E_BAD_ARGS;
				goto exit;
			}

			if (root_ca)
				free(root_ca);

			root_ca = malloc(st.st_size + 1);
			if (!root_ca) {
				fclose(f);
				ret = E_NO_MEM;
				goto exit;
			}
			if (!fread(root_ca, st.st_size, 1, f)) {
				printf("Failed to read root CA file\n");
				fclose(f);
				ret = E_BAD_ARGS;
				goto exit;
			}

			fclose(f);
			break;
		default:
			printf("Usage: cloud-test [-t <access token>]"\
				" [-d <device id>] [-u <user id>] \r\n");
			printf("\t[-p <app id>] [-m <JSON type message>]"\
				" [-a <JSON type action>] \r\n");
			printf("\t[-r <CA root file>]"\
				" [-y <device type id>]"\
				" [-b <data JSON>] [-s enables timestamp]\r\n");
			printf("\t[-v for verifying root certificate]\r\n");
			return 0;
		}
	}

	if (root_ca) {
		ssl_config.ca_cert.data = strdup(root_ca);
		ssl_config.ca_cert.len = strlen(root_ca);
	}

	ret = test_get_user_profile(token, ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_get_user_devices(token, user_id, ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_get_user_device_types(token, user_id, ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_get_user_application_properties(token, user_id, app_id,
								ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_get_device(token, device_id, ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_get_device_token(token, device_id, ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_cloud_message(token, device_id, message, ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_cloud_action(token, device_id, action, ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_update_device_token(token, device_id, ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_delete_device_token(token, device_id, ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_add_delete_device(token, user_id, device_type_id,
							ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_set_device_server_properties(token, device_id, data,
							ssl_config);
	if (ret != S_OK)
		goto exit;

	ret = test_get_device_properties(token, device_id, timestamp,
							ssl_config);

exit:
	if (token != NULL)
		free(token);
	if (device_id != NULL)
		free(device_id);
	if (user_id != NULL)
		free(user_id);
	if (app_id != NULL)
		free(app_id);
	if (message != NULL)
		free(message);
	if (action != NULL)
		free(action);
	if (device_type_id != NULL)
		free(device_type_id);
	if (data != NULL)
		free(data);
	if (root_ca != NULL)
		free(root_ca);
	if (ssl_config.ca_cert.data != NULL)
		free(ssl_config.ca_cert.data);

	return (ret == S_OK) ? 0 : -1;
}
