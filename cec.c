/*
 *  Squeezelite - lightweight headless squeezebox emulator
 *
 *  (c) Adrian Smith 2012-2015, triode1@btinternet.com
 *      Ralph Irving 2015-2023, ralph_irving@hotmail.com
 *  
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// HDMI CEC thread - linux only

#if HDMICEC

#define _GNU_SOURCE

#include <libcec/cecc.h>
#include <libcec/cectypes.h>
#include <ctype.h>

#include "squeezelite.h"

static log_level loglevel;

#if !LINKALL
struct cec_func {
	void (*libcec_clear_configuration)(CEC_NAMESPACE libcec_configuration *configuration);
	void (*libcec_close)(libcec_connection_t connection);
	int8_t (*libcec_detect_adapters)(libcec_connection_t connection, CEC_NAMESPACE cec_adapter_descriptor *deviceList, uint8_t iBufSize, const char *strDevicePath, int bQuickScan);
	void (*libcec_destroy)(libcec_connection_t connection);
	int (*libcec_get_current_configuration)(libcec_connection_t connection, CEC_NAMESPACE libcec_configuration *configuration);
	libcec_connection_t (*libcec_initialise)(CEC_NAMESPACE libcec_configuration *configuration);
	void (*libcec_init_video_standalone)(libcec_connection_t connection);
	
	CEC_NAMESPACE cec_power_status (*libcec_get_device_power_status)(libcec_connection_t connection, cec_logical_address iLogicalAddress);
	int (*libcec_open)(libcec_connection_t connection, const char *strPort, uint32_t iTimeout);
	int (*libcec_power_on_devices)(libcec_connection_t connection, CEC_NAMESPACE cec_logical_address iLogicalAddress);
	int (*libcec_standby_devices)(libcec_connection_t connection, CEC_NAMESPACE cec_logical_address iLogicalAddress);
	int (*libcec_system_audio_mode)(libcec_connection_t connection, int bEnable);
	u8_t (*libcec_system_audio_mode_get_status)(libcec_connection_t connection);
	u8_t (*libcec_audio_get_status)(libcec_connection_t connection);
	int (*libcec_volume_up)(libcec_connection_t connection, int bSendRelease);
	int (*libcec_volume_down)(libcec_connection_t connection, int bSendRelease);
	int (*libcec_mute_audio)(libcec_connection_t connection, int bSendRelease); 
	CEC_NAMESPACE cec_logical_address (*libcec_get_active_source)(libcec_connection_t connection);

	void (*libcec_logical_address_to_string)(const CEC_NAMESPACE cec_logical_address address, char *buf, size_t bufsize);
	void (*libcec_system_audio_status_to_string)(const CEC_NAMESPACE cec_system_audio_status, char* buf, size_t bufsize);
	void (*libcec_power_status_to_string)(const CEC_NAMESPACE cec_power_status, char *buf, size_t bufsize);
};

static struct cec_func *i;
#endif

#if LINKALL
#define CEC(h, fn, ...) (libcec_ ## fn)(__VA_ARGS__)
#else
#define CEC(h, fn, ...) (h)->libcec_ ## fn(__VA_ARGS__)
#endif

#if !LINKALL
static bool load_cec() {
	void *handle = dlopen(LIBCEC, RTLD_NOW);
	char *err;

	if (!handle) {
		LOG_INFO("dlerror: %s", dlerror());
		return false;
	}

	i->libcec_clear_configuration = dlsym(handle, "libcec_clear_configuration");
	i->libcec_close = dlsym(handle, "libcec_close");
	i->libcec_detect_adapters = dlsym(handle, "libcec_detect_adapters");
	i->libcec_destroy = dlsym(handle, "libcec_destroy");
	i->libcec_get_current_configuration = dlsym(handle, "libcec_ger_current_configuration");
	i->libcec_initialise = dlsym(handle, "libcec_initialise");
	i->libcec_init_video_standalone = dlsym(handle, "libcec_init_video_standalone");
	i->libcec_open = dlsym(handle, "libcec_open");
	i->libcec_get_device_power_status = dlsym(handle, "libcec_get_device_power_status");
	i->libcec_power_on_devices = dlsym(handle, "libcec_power_on_devices");
	i->libcec_standby_devices = dlsym(handle, "libcec_standby_devices");
	i->libcec_system_audio_mode = dlsym(handle, "libcec_system_audio_mode");
	i->libcec_system_audio_mode_get_status = dlsym(handle, "libcec_system_audio_mode_get_status");
	i->libcec_audio_get_status = dlsym(handle, "libcec_audio_get_status");
	i->libcec_volume_up = dlsym(handle, "libcec_volume_up");
	i->libcec_volume_down = dlsym(handle, "libcec_volume_down");
	i->libcec_mute_audio = dlsym(handle, "libcec_mute_audio");
	i->libcec_get_active_source = dlsym(handle, "libcec_get_active_source");

	i->libcec_logical_address_to_string = dlsym(handle, "libcec_logical_address_to_string");
	i->libcec_system_audio_status_to_string = dlsym(handle, "libcec_system_audio_status_to_string");
	i->libcec_power_status_to_string = dlsym(handle, "libcec_power_status_to_string");

	if ((err = dlerror()) != NULL ) {
		LOG_INFO("dlerror: %s", err);
		return false;
	}

	LOG_INFO("loaded "LIBCEC);
	return true;
}
#endif

#define cond_type pthread_cond_t
#define cond_create(c) pthread_cond_init(&c, NULL)
#define cond_destroy(c) pthread_cond_destroy(&c)

#define CEC_CLIENT_ID "SqueezeLite"
#define CEC_CLIENT_DEVICE_TYPE CEC_DEVICE_TYPE_PLAYBACK_DEVICE;
#define CEC_THREAD_TIMEOUT_MS 1000
#define CEC_POWER_CHANGE_WAIT_TIMEOUT_MS 1000
#define CEC_POWER_STATE_TRANSITION_TIMEOUT_MS 10000
#define LOCK_CEC mutex_lock(cec.mutex);
#define UNLOCK_CEC mutex_unlock(cec.mutex);
#define CONDWAIT_SQ(t) pthread_cond_reltimedwait(&cec.cond_sq, &cec.mutex, t);
#define CONDSIGNAL_SQ pthread_cond_signal(&cec.cond_sq);
#define CONDWAIT_CEC(t) pthread_cond_reltimedwait(&cec.cond_cec, &cec.mutex, t);
#define CONDSIGNAL_CEC pthread_cond_signal(&cec.cond_cec);

#define LMSCLI_PORT 9090
#define LMSCLI_SEND_SLEEP (10000)
#define LMSCLI_SEND_TO (1*500000)
#define LMSCLI_KEEP_DURATION (15*60*1000)
#define LMSCLI_PACKET 4096
#define SQ_TOTAL_VOLUME_RANGE_DB -74
#define SQ_STEP_POINT 25
#define SQ_STEP_FRACTION .5
#define SQ_MAXIMUM_VOLUME_DB 0
#define LOCK_SQ mutex_lock(sq.mutex);
#define UNLOCK_SQ mutex_unlock(sq.mutex);

static bool running;

typedef struct {
	mutex_type mutex;
	struct _cec_queue_s  {
		struct _cec_queue_s *next;
		void *item;
	} head, *walker;
} cec_queue_t;

typedef struct cec_req_s {
	char type[20];
	union payload_s {
		struct {
			cec_power_status target;
			u32_t timeout_ms;
		} power;
		u8_t volume;
	} payload;
} cec_req_t;

typedef enum {
	UNKNOWN, MUTED, UNMUTED
} cec_mute_state_t;

typedef struct cec_s {
	libcec_configuration config;
	libcec_connection_t connection;
        int loglevel;
	sq_event_t sq_power;
	bool sq_fade_active;
	u8_t sq_volume;
	cec_mute_state_t sq_mute;
	u32_t volume_stamp_rx;
	u32_t volume_stamp_tx;
	bool device_not_active;
	cec_power_status device_power;
	cec_system_audio_status device_audio_mode;
	u8_t device_volume;
	cec_mute_state_t device_mute;
	char strComName[1024];
	char strComPath[1024];
	cec_queue_t queue;
	mutex_type mutex;
	cond_type cond_cec;
	cond_type cond_sq;
} cec_t;

struct cec_s cec;
struct sqcli_s sq;
thread_type device_thread;
thread_type sq_thread;

static void cb_cec_log_message(void *libcec, const cec_log_message *message);

static ICECCallbacks cec_callbacks = {
	.logMessage		= cb_cec_log_message,
	.keyPress		= NULL,
	.commandReceived	= NULL,
	.configurationChanged	= NULL,
	.alert			= NULL,
	.menuStateChanged	= NULL,
	.sourceActivated	= NULL
};

void cec_queue_init(cec_queue_t *queue) {
	queue->head.item = NULL;
	mutex_create(queue->mutex);
}

int pthread_cond_reltimedwait(cond_type *cond, mutex_type *mutex, u32_t msWait) {
	struct timespec ts;
	u32_t nsec;

	clock_gettime(CLOCK_REALTIME, &ts);

	if (!msWait)
		return pthread_cond_wait(cond, mutex);

	nsec = ts.tv_nsec + (msWait % 1000) * 1000000;
	ts.tv_sec += msWait / 1000 + (nsec / 1000000000);
	ts.tv_nsec = nsec % 1000000000;

	return pthread_cond_timedwait(cond, mutex, &ts);
}

void cec_queue_insert(cec_queue_t *queue, void *item) {
	struct _cec_queue_s *list;

	mutex_lock(queue->mutex);

	list = &queue->head;
	while (list->item)
		list = list->next;
	list->item = item;
	list->next = malloc(sizeof(struct _cec_queue_s));
	list->next->item = NULL;

	mutex_unlock(queue->mutex);
}

void cec_queue_insert_first(cec_queue_t *queue, void *item) {
	struct _cec_queue_s * next;

	mutex_lock(queue->mutex);

	next = malloc(sizeof(struct _cec_queue_s));
	memcpy(next, &queue->head, sizeof(struct _cec_queue_s));
	queue->head.item = item;
	queue->head.next = next;

	mutex_unlock(queue->mutex);
}

void *cec_queue_extract(cec_queue_t *queue) {
	mutex_lock(queue->mutex);

	void *item = queue->head.item;

	if (item) {
		struct _cec_queue_s *next = queue->head.next;
		queue->head.item = next->item;
		queue->head.next = next->next;
		free(next);
	}

	mutex_unlock(queue->mutex);

	return item;
}

void cec_queue_flush(cec_queue_t *queue) {
	struct _cec_queue_s *walker;

	mutex_lock(cec.queue.mutex);

	walker = &queue->head;

	while(walker->item) {
		struct _cec_queue_s *next = walker->next;
		if (walker != &queue->head) {
			do {
				if (walker) {
					free(walker);
					walker = NULL;	
				}
			} while(0); 
		}
		walker = next;  
	}
	if (walker != &queue->head)
		free(walker);
	queue->head.item = NULL;

	mutex_unlock(cec.queue.mutex);
}

/* Converts CEC volume [0 .. 100] to SQ gain [-74dB .. 0dB] */
/* This is the conversion done in Squeezeplay.pm */
float map_volume_to_dB(float volume) {
	float dB;
	float total_volume_range_dB = SQ_TOTAL_VOLUME_RANGE_DB;
	float maximum_volume_dB = SQ_MAXIMUM_VOLUME_DB;
	float step_point = SQ_STEP_POINT;
	float step_fraction = SQ_STEP_FRACTION;

	float step_dB = total_volume_range_dB * step_fraction;

	float m, x1, y1;	
	if (volume > step_point) {
		m = (maximum_volume_dB - step_dB) / (100 - step_point);
		x1 = step_point;
		y1 = step_dB;
	}
	else {
		m = (step_dB - total_volume_range_dB) / (step_point - 0);
		x1 = maximum_volume_dB;
		y1 = total_volume_range_dB;
	}

	dB = m * (volume - x1) + y1;

	return dB;
} 

/* Converts SQ gain [-74dB .. 0dB] to CEC volume [0 .. 100] */
/* This conversion is based on the conversion done in Squeezeplay.pm */
u8_t map_dB_to_volume(float dB) {
	u8_t volume;
	float total_volume_range_dB = SQ_TOTAL_VOLUME_RANGE_DB;
	float maximum_volume_dB = SQ_MAXIMUM_VOLUME_DB;
	float step_point = SQ_STEP_POINT;
	float step_fraction = SQ_STEP_FRACTION;

	float step_dB = total_volume_range_dB * step_fraction;

	float m, x1, y1;
	if (dB > step_dB) {
		m = (maximum_volume_dB - step_dB) / (100 - step_point);
		x1 = step_point;
		y1 = step_dB;
	}
	else {
		m = (step_dB - total_volume_range_dB) / (step_point - 0);
		x1 = 0;
		y1 = total_volume_range_dB;
	}

	volume = (u8_t)round((dB - y1) / m + x1);

	return volume;
}

/* Converts a hex character to its integer value */
static char from_hex(char ch) {
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
static char to_hex(char code) {
	static char hex[] = "0123456789abcdef";

	return hex[code & 15];
}

int sq_cli_open_socket(void) {
	struct sockaddr_in addr;

	sq.socket = socket(AF_INET, SOCK_STREAM, 0);
	set_nonblock(sq.socket);
	set_nosigpipe(sq.socket);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = sq.server_ip;
	addr.sin_port = htons(LMSCLI_PORT);

	if (connect_timeout(sq.socket, (struct sockaddr *) &addr, sizeof(addr), 250))  {
		LOG_ERROR("unable to connect to server via LMSCLI");
		closesocket(sq.socket);
		sq.socket = -1;
		return 0;
	}

	LOG_SDEBUG("opened LMSCLI socket %d", sq.socket);

	return 1;
}

/* IMPORTANT: be sure to free() the returned string after use */
static char *sq_cli_encode(char *str) {
	char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
	while (*pstr) {
		if ( isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' ||
					*pstr == '~' || *pstr == ' ' || *pstr == ')' ||
					*pstr == '(' )
			*pbuf++ = *pstr;
		else if (*pstr == '%') {
			*pbuf++ = '%',*pbuf++ = '2', *pbuf++ = '5';
		}
		else {
			*pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
		}
		pstr++;
	}
	*pbuf = '\0';

	return buf;
}

/* IMPORTANT: be sure to free() the returned string after use */
static char *sq_cli_decode(char *str) {
	char *pstr = str, *buf = malloc(strlen(str) + 1), *pbuf = buf;
	while (*pstr) {
		if (*pstr == '%') {
			if (pstr[1] && pstr[2]) {
				*pbuf++ = (from_hex(pstr[1]) << 4) | from_hex(pstr[2]);
				pstr += 2;
			}
		}
		else {
			*pbuf++ = *pstr;
		}
		pstr++;
	}
	*pbuf = '\0';

	return buf;
}

void sq_cli_send_packet(u8_t *packet, size_t len, sockfd sock) {
	u8_t *ptr = packet;
	unsigned try = 0;
	ssize_t n;

	while (len) {
		n = send(sock, ptr, len, MSG_NOSIGNAL);
		if (n <= 0) {
			int error = last_error();
#if WIN
			if (n < 0 && (error == ERROR_WOULDBLOCK || error == WSAENOTCONN) && try < 10) {
#else
			if (n < 0 && error == ERROR_WOULDBLOCK && try < 10) {
#endif
				LOG_SDEBUG("[%d]: retrying (%d) writing to socket", sock, ++try);
				usleep(1000);
				continue;
			}
			LOG_WARN("[%d]: failed writing to socket: %s", sock, strerror(last_error()));
			return;
		}
		ptr += n;
		len -= n;
	}
}

char *sq_cli_send_command(char *command, bool request, bool decode) {
	char *packet;
	int wait;
	size_t len;
	char *response = NULL;

	LOCK_SQ;

	if (!sq_cli_open_socket()) {
		UNLOCK_SQ;
		return NULL;
	}

	packet = malloc(LMSCLI_PACKET + 1);
	sq.timeout = gettime_ms() + LMSCLI_KEEP_DURATION;
	wait = LMSCLI_SEND_TO / LMSCLI_SEND_SLEEP;

	command = sq_cli_encode(command);

	if (request)
		len = sprintf(packet, "%s ?\n", command);
	else
		len = sprintf(packet, "%s \n", command);

	LOG_SDEBUG("command %s", packet);

	sq_cli_send_packet((u8_t*) packet, len, sq.socket);

	// first receive the tag and then point to the last '\n'
	len = 0;

	while (wait) {
		int k;
		fd_set rfds;
		struct timeval timeout = {0, LMSCLI_SEND_SLEEP};

		FD_ZERO(&rfds);
		FD_SET(sq.socket, &rfds);

		k = select(sq.socket + 1, &rfds, NULL, NULL, &timeout);

		if (!k) {
			wait --;
			continue;
		}

		if (k < 0)
			break;

		k = recv(sq.socket, packet + len, LMSCLI_PACKET - len, 0);

		if (k <= 0)
			break;

		len += k;
		packet[len] = '\0';
		if (strchr(packet, '\n') && strcasestr(packet, command)) {
			response = packet;
			break;
		}
	}

	if (!wait)
		LOG_WARN("Timeout waiting for CLI reponse (%s)", command);

	LOG_SDEBUG("response %s", response);

	if (response && ((response = strcasestr(response, command)) != NULL)) {
		response += strlen(command);
		while (*response && *response == ' ')
			response++;

		if (decode)
			response = sq_cli_decode(response);
		else
			response = strdup(response);

		*(strrchr(response, '\n')) = '\0';
	}

	UNLOCK_SQ;

	free(command);
	free(packet);

	return response;
}

void sq_notify(sq_event_t event, ...) {
	char command[128] = "";
	char *response;

	LOG_SDEBUG("notify LMS server %d", event);

	va_list args;
	va_start(args, event);

	LOCK_SQ;
	switch (event) {
		case SQ_ON:
			sprintf(command, "%s power 1", sq.client_id);
			break;
		case SQ_OFF:
			sprintf(command, "%s power 0", sq.client_id);
			break;
		case SQ_MUTE:
			sprintf(command, "%s mixer muting 1", sq.client_id);
			break;
		case SQ_UNMUTE:
			sprintf(command, "%s mixer muting 0", sq.client_id);
			break;
		case SQ_VOLUME: {
			int volume = va_arg(args, int);
			sprintf(command, "%s mixer volume %d", sq.client_id, volume);
			}
			break;
		default:
			break;
	}

	va_end(args);

	UNLOCK_SQ;

	if (*command) {
		response = sq_cli_send_command(command, false, true);
		free(response);
	}
}

static void cb_cec_log_message(void *libcec, const cec_log_message *message) {
	if ((message->level & cec.loglevel) == message->level) {	
		switch (message->level) {
			case CEC_LOG_ERROR:
				LOG_SDEBUG("[LIBCEC ERROR] %s", message->message);
				break;
			case CEC_LOG_WARNING:
				LOG_SDEBUG("[LIBCEC WARNING] %s", message->message);
				break;
			case CEC_LOG_NOTICE:
				LOG_SDEBUG("[LIBCEC NOTICE] %s", message->message);
				break;
			case CEC_LOG_TRAFFIC:
				LOG_SDEBUG("[LIBCEC TRAFFIC] %s", message->message);
				break;
			case CEC_LOG_DEBUG:
				LOG_SDEBUG("[LIBCEC DEBUG] %s", message->message);
				break;
			default:
				break;
		}
	}
}

int cec_other_device_active() {
	cec_logical_address address_active_source = CEC(i, get_active_source, cec.connection);
	if (libcec_is_active_source(cec.connection, address_active_source) && address_active_source != cec.config.logicalAddresses.primary && address_active_source != CECDEVICE_UNKNOWN) {
		char str_active_source[50];
		CEC(i, logical_address_to_string, address_active_source, str_active_source, sizeof(str_active_source)); 
		LOG_DEBUG("CEC: found other device being active source (%s)", str_active_source);

		return 1;
	}
	else {
		return 0;
	}
}

int sq_callback(sq_event_t event, ...) {
	int rc = 1;

	va_list args;
	va_start(args, event);

	LOCK_CEC;

	switch (event) {
		case SQ_ONOFF: {
			int on = va_arg(args, int); 
			sq_event_t sq_param;

			LOG_DEBUG("SQ: reveived SQ_ONOFF (%d)", on);
			sq_param = (on == 1) ? SQ_ON : SQ_OFF;

			if (cec.sq_power != sq_param) {
				cec.sq_power = sq_param;

				if (cec.sq_power == SQ_ON) {
					cec_req_t *req = malloc(sizeof(cec_req_t));
					strcpy(req->type, "SET_POWER_ON");
					cec_queue_insert(&cec.queue, req);
					CONDSIGNAL_SQ;
				}
				else if (cec.sq_power == SQ_OFF) {
					cec_req_t *req = malloc(sizeof(cec_req_t));
					strcpy(req->type, "SET_AUDIOMODE_OFF");
					cec_queue_insert(&cec.queue, req);
					CONDSIGNAL_SQ;
				}
			}
			break;
		}

		case SQ_CONNECT: {
			LOG_DEBUG("SQ: received SQ_CONNECT");
			if (cec.device_audio_mode == CEC_SYSTEM_AUDIO_STATUS_OFF
				|| cec.device_audio_mode == CEC_SYSTEM_AUDIO_STATUS_UNKNOWN) {
				cec_req_t *req = malloc(sizeof(cec_req_t));
				strcpy(req->type, "SET_AUDIOMODE_ON");
				cec_queue_insert(&cec.queue, req);
				CONDSIGNAL_SQ;
			}
			break;
		}

		case SQ_FADE: {
			int active = va_arg(args, int);
			LOG_DEBUG("SQ: received SQ_FADE (%d)", active);
			cec.sq_fade_active = active;
			break;
		}

		case SQ_MUTE_TOGGLE: {
			int mute = va_arg(args, int);

			LOG_DEBUG("SQ: received SQ_MUTE_TOGGLE (%d)", mute);
			u32_t now = gettime_ms();

			if (mute && now > cec.volume_stamp_tx + 1000) {
				cec_req_t *req = malloc(sizeof(cec_req_t));
				strcpy(req->type, "SET_MUTE");
				cec_queue_insert(&cec.queue, req);
				CONDSIGNAL_SQ;
			}
			else if (!mute && now > cec.volume_stamp_tx + 1000) {
				cec_req_t *req = malloc(sizeof(cec_req_t));
 				strcpy(req->type, "SET_UNMUTE");
				cec_queue_insert(&cec.queue, req);
				CONDSIGNAL_SQ;
			}
			break;
		}

		case SQ_VOLUME: {
			int gainL = va_arg(args, int);
			int gainR = va_arg(args, int);

			if (cec.sq_fade_active) {
				LOG_DEBUG("SQ: received SQ_VOLUME (%d, %d), but ignoring.", gainL, gainR);	
				break;
			}

			float dB = 20 * log10( ((float)gainL + (float)gainR) * .5 / 65536.0F );
			u32_t now = gettime_ms();

			u8_t volume = map_dB_to_volume(dB);

			if (cec.sq_volume == CEC_AUDIO_VOLUME_STATUS_UNKNOWN ||
				volume != cec.sq_volume
				|| now > cec.volume_stamp_tx + 1000) {
				cec_req_t *req = malloc(sizeof(cec_req_t));
				strcpy(req->type, "SET_VOLUME");
				req->payload.volume = volume;
				cec_queue_insert(&cec.queue, req);
				CONDSIGNAL_SQ;
			}
			break;
		}

		default:
			break;
	}
	UNLOCK_CEC;

	return rc;
}

void *request_thread() {
	running = true;

	while (running) {
		LOCK_CEC;

		cec_req_t *req_recv = cec_queue_extract(&cec.queue);

		if (req_recv) {
			LOG_DEBUG("SQ >> CEC: incoming request: %s", req_recv->type);
			if (!strcasecmp(req_recv->type, "SET_POWER_ON")) {
				if (cec.device_power != CEC_POWER_STATUS_ON) {
					CEC(i, power_on_devices, cec.connection, CECDEVICE_AUDIOSYSTEM);

					cec_req_t *req_snd = malloc(sizeof(cec_req_t));
					strcpy(req_snd->type, "WAIT_POWER_CHANGE");
					req_snd->payload.power.target = CEC_POWER_STATUS_ON;
					req_snd->payload.power.timeout_ms = CEC_POWER_STATE_TRANSITION_TIMEOUT_MS;
					cec_queue_insert_first(&cec.queue, req_snd);
				}
				else {
					cec_req_t *req_snd = malloc(sizeof(cec_req_t));
					strcpy(req_snd->type, "SET_AUDIOMODE_ON");
					cec_queue_insert_first(&cec.queue, req_snd);
				}
			}
			if (!strcasecmp(req_recv->type, "SET_POWER_STANDBY")) {
				CEC(i, standby_devices, cec.connection, CECDEVICE_AUDIOSYSTEM);

				cec_req_t *req_snd = malloc(sizeof(cec_req_t));
				strcpy(req_snd->type, "WAIT_POWER_CHANGE");
				req_snd->payload.power.target = CEC_POWER_STATUS_STANDBY;
				req_snd->payload.power.timeout_ms = CEC_POWER_STATE_TRANSITION_TIMEOUT_MS;
				cec_queue_insert_first(&cec.queue, req_snd);
			}
			if (!strcasecmp(req_recv->type, "WAIT_POWER_CHANGE")) {
				u32_t starttime_ms = gettime_ms();

				do {
					if (gettime_ms() - starttime_ms >= CEC_POWER_CHANGE_WAIT_TIMEOUT_MS)
						cec.device_power = CEC(i, get_device_power_status, cec.connection, CECDEVICE_AUDIOSYSTEM);

				} while (cec.device_power != req_recv->payload.power.target && (gettime_ms() - starttime_ms < req_recv->payload.power.timeout_ms));

				LOG_DEBUG("SQ >> CEC: power change cycle finished");

				if (req_recv->payload.power.target == CEC_POWER_STATUS_ON) {
					cec_req_t *req_snd = malloc(sizeof(cec_req_t));
					strcpy(req_snd->type, "SET_AUDIOMODE_ON");
					cec_queue_insert_first(&cec.queue, req_snd);
				}
			}
			if (!strcasecmp(req_recv->type, "SET_AUDIOMODE_ON")) {
				CEC(i, system_audio_mode, cec.connection, true);
			}
			if (!strcasecmp(req_recv->type, "SET_AUDIOMODE_OFF")) {
				CEC(i, system_audio_mode, cec.connection, false);

				cec_req_t *req_snd = malloc(sizeof(cec_req_t));
				strcpy(req_snd->type, "SET_POWER_STANDBY");
				cec_queue_insert_first(&cec.queue, req_snd);
			}
			if (!strcasecmp(req_recv->type, "SET_MUTE")) {
				if (cec.device_audio_mode == CEC_SYSTEM_AUDIO_STATUS_ON && cec.device_power == CEC_POWER_STATUS_ON) {

					cec.device_volume = CEC(i, audio_get_status, cec.connection);
					cec.sq_mute = MUTED;

					if ((cec.device_volume & CEC_AUDIO_MUTE_STATUS_MASK) != CEC_AUDIO_MUTE_STATUS_MASK
						|| !cec.device_mute) {
						LOG_DEBUG("SQ >> CEC: cec.sq_mute (%d), cec.device_mute (%d). muting CEC device",
								cec.sq_mute, cec.device_mute);
						CEC(i, mute_audio, cec.connection, true);
						cec.device_mute = MUTED;
					}
				}
			}
			if (!strcasecmp(req_recv->type, "SET_UNMUTE")) {
				if (cec.device_audio_mode == CEC_SYSTEM_AUDIO_STATUS_ON && cec.device_power == CEC_POWER_STATUS_ON) {

					cec.device_volume = CEC(i, audio_get_status, cec.connection);
					cec.sq_mute = UNMUTED;

					if ((cec.device_volume & CEC_AUDIO_MUTE_STATUS_MASK) == CEC_AUDIO_MUTE_STATUS_MASK
						|| cec.device_mute) {
						LOG_DEBUG("SQ >> CEC: cec.sq_mute (%d), cec.device_mute (%d). unmuting CEC device",
								cec.sq_mute, cec.device_mute);
						CEC(i, mute_audio, cec.connection, true);
						cec.device_mute = UNMUTED;
					}
				}
			}
			if (!strcasecmp(req_recv->type, "SET_VOLUME")) {
				if (cec.device_audio_mode == CEC_SYSTEM_AUDIO_STATUS_ON && cec.device_power == CEC_POWER_STATUS_ON) {

					u8_t audio_status = CEC(i, audio_get_status, cec.connection);
					cec.device_volume = audio_status & ~CEC_AUDIO_MUTE_STATUS_MASK;

					cec.sq_volume = req_recv->payload.volume;

					int delta = cec.sq_volume - cec.device_volume;
					int current_volume = cec.device_volume;
					int delta_start = delta;

					/*
					 * if everything is muted there is no delta between the volumes.
					 * so do not set the volume - this would unmute the CEC device.
					 *
					 */
					if (((cec.device_volume & CEC_AUDIO_MUTE_STATUS_MASK) == CEC_AUDIO_MUTE_STATUS_MASK || cec.device_mute == MUTED)
						&& cec.sq_mute)
						delta = 0;

					LOG_DEBUG("cec.sq_volume: %d, cec.device_volume: %d, delta: %d", cec.sq_volume, cec.device_volume, delta);

					while (delta != 0) {
						/*
						 * The following code avoids asking for the audio status of the CEC device.
						 *  Thus, it should be faster to steer the CEC device's volume, due to the missing
						 * call which would take additional 200-250ms.
						 * Let's hope this is stable enough.
						 */
						if (delta > 0) {
							current_volume = cec.device_volume + (delta_start - delta);
							LOG_DEBUG("SQ >> CEC: sq_volume: %d, device_volume: %d, delta: %d", cec.sq_volume, current_volume, delta);
							CEC(i, volume_up, cec.connection, true);
							usleep(250*1000);
							delta--;
						}
						else if (delta < 0) {
							current_volume = cec.device_volume + (delta_start - delta);
							LOG_DEBUG("SQ >> CEC: sq_volume: %d, device_volume: %d, delta: %d", cec.sq_volume, current_volume, delta);
                                                        CEC(i, volume_down, cec.connection, true);
                                                        usleep(250*1000); 
                                                        delta++;
						}
					}

					if (delta_start != 0) {
						//LOG_DEBUG("SQ >> CEC: volume event processed");
					}
					else {
						//LOG_DEBUG("SQ >> CEC: no volume update needed.");
					}
				}
				else {
					//LOG_DEBUG("SQ >> CEC: not in audio mode. skipping volume.");
				}
			}
			free(req_recv);
		}
		else {
			LOG_DEBUG("SQ >> CEC: no pending requests in queue. waiting.");
			CONDSIGNAL_CEC;
			CONDWAIT_SQ(CEC_THREAD_TIMEOUT_MS);
			
		}

		UNLOCK_CEC;

	}

        return NULL;
}

static void *cec_thread() {
	running = true;

	while (running) {
		LOCK_CEC;

		CONDWAIT_CEC(0);

		cec.device_power = CEC(i, get_device_power_status, cec.connection, CECDEVICE_AUDIOSYSTEM);
		cec.device_audio_mode = CEC(i, system_audio_mode_get_status, cec.connection);
		cec.device_not_active = 0; //cec_other_device_active();

		/* send the cec device state to sq. */
		if (cec.device_power == CEC_POWER_STATUS_ON && cec.sq_power == SQ_OFF) {
			LOG_DEBUG("CEC >> SQ: cec switched to on. switching sq_power to on");
			cec.sq_power = SQ_ON;
			sq_notify(cec.sq_power);
		}
		if (cec.device_power == CEC_POWER_STATUS_STANDBY && cec.sq_power == SQ_ON) {
			LOG_DEBUG("CEC >> SQ: cec switched to off. switching sq_power to off");
			cec.sq_power = SQ_OFF;
			sq_notify(cec.sq_power);
		}
		if (!cec.device_not_active && cec.device_audio_mode == CEC_SYSTEM_AUDIO_STATUS_ON) {
			u32_t now = gettime_ms();
			cec.device_volume = CEC(i, audio_get_status, cec.connection);
			//LOG_DEBUG("CEC >> SQ: audio_status is %02x (%d)", cec.device_volume, cec.device_volume);

			// does volume change unmute or is specific unmute needed?
			if (((cec.device_volume & CEC_AUDIO_MUTE_STATUS_MASK) != CEC_AUDIO_MUTE_STATUS_MASK || cec.device_volume > 0)
				&& (cec.device_volume & ~CEC_AUDIO_MUTE_STATUS_MASK) != cec.sq_volume && now > cec.volume_stamp_tx + 1000) {
				LOG_DEBUG("CEC >> SQ: cec.sq_volume: %d (mute: %d), cec.device_volume: %d (mute: %d)",
						cec.sq_volume, cec.sq_mute, cec.device_volume, cec.device_mute); 
				LOG_DEBUG("CEC >> SQ: send volume update");
				cec.volume_stamp_tx = now;
				//sq_notify(SQ_VOLUME, cec.device_volume);
			}
			else if (((cec.device_volume & CEC_AUDIO_MUTE_STATUS_MASK) == CEC_AUDIO_MUTE_STATUS_MASK || cec.device_volume == 0)
				&& now > cec.volume_stamp_tx + 1000) {
				LOG_DEBUG("CEC >> SQ: send mute update");
				cec.volume_stamp_tx = now;
				//sq_notify(SQ_MUTE);
			}
		}

		UNLOCK_CEC;
	}

	return NULL;
}

void cec_init(log_level level) {
	loglevel = level;
	cec.loglevel = -1;

#if !LINKALL
	i = malloc(sizeof(struct cec_func));
	if (i || !load_cec()) {
		return;
	}
#endif

	CEC(i, clear_configuration, &cec.config);
	cec.config.clientVersion = LIBCEC_VERSION_CURRENT;
	cec.config.bActivateSource = 0;

	cec.config.callbacks = &cec_callbacks;
	cec.config.deviceTypes.types[0] = CEC_CLIENT_DEVICE_TYPE;
	snprintf(cec.config.strDeviceName, sizeof(cec.config.strDeviceName), CEC_CLIENT_ID);

	cec.connection = CEC(i, initialise, &cec.config);
	CEC(i, init_video_standalone, cec.connection);

	if (cec.loglevel == -1)
		cec.loglevel = CEC_LOG_DEBUG;

	if (strcmp(cec.strComName, "") == 0) {
		cec_adapter_descriptor devices[10];
		int iDevicesFound;

		LOG_DEBUG("autodetecting hdmi port");

		iDevicesFound = CEC(i, detect_adapters, cec.connection, devices, 10, NULL, true);

		if (iDevicesFound < 0) {
			LOG_ERROR("autodection of hdmi port failed");
		}
		else if (iDevicesFound == 0) {
			LOG_DEBUG("no hdmi port found.");
		}
		else {
			LOG_DEBUG("autodetected path: %s, com name: %s",
					devices[0].strComPath, devices[0].strComName);
			strcpy(cec.strComName, devices[0].strComName);
			strcpy(cec.strComPath, devices[0].strComPath);
		}
	}

	if (!CEC(i, open, cec.connection, cec.strComName, 10000)) {
		LOG_ERROR("unable to open hdmi port %s", cec.strComName);
	}
	else {
		char logical_addr_str[50];

		CEC(i, get_current_configuration, cec.connection, &cec.config);

		CEC(i, logical_address_to_string, cec.config.logicalAddresses.primary, logical_addr_str, sizeof(logical_addr_str));
		LOG_DEBUG("connection opened on HDMI port '%s' as '%s' (%d) with physical address '%x.%x.%x.%x'",
			cec.strComPath, logical_addr_str, cec.config.logicalAddresses.primary,
			(cec.config.iPhysicalAddress >> 12) & 0xf, (cec.config.iPhysicalAddress >> 8) & 0xf,
			(cec.config.iPhysicalAddress >> 4) & 0xf, cec.config.iPhysicalAddress & 0xf);
	}

	LOCK_SQ;
	sq.socket = -1;
	sq.server_ip = -1;
	UNLOCK_SQ;

	cec.device_power = CEC_POWER_STATUS_UNKNOWN;
	cec.device_audio_mode = CEC_SYSTEM_AUDIO_STATUS_UNKNOWN;
	cec.sq_power = SQ_OFF;
        cec.sq_volume = CEC_AUDIO_VOLUME_STATUS_UNKNOWN;
	cec.sq_mute = UNKNOWN;
        cec.device_volume = CEC_AUDIO_VOLUME_STATUS_UNKNOWN;
	cec.device_mute = UNKNOWN;
	cec.volume_stamp_rx = cec.volume_stamp_tx = gettime_ms() - 2000;
	cec.device_not_active = cec_other_device_active();

	cec_queue_init(&cec.queue);
	mutex_create(cec.mutex);
	cond_create(cec.cond_cec);
	cond_create(cec.cond_sq);

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN + CEC_THREAD_STACK_SIZE);
	pthread_create(&device_thread, &attr, cec_thread, NULL);
	pthread_create(&sq_thread, NULL, request_thread, NULL);
	pthread_attr_destroy(&attr);
}

void cec_close(void) {
	LOG_INFO("closing CEC thread");

	LOCK_CEC;
	running = false;
	UNLOCK_CEC;

	LOG_DEBUG("closing CEC connection");
	CEC(i, close, cec.connection);
	LOG_DEBUG("destroying CEC connection");
	CEC(i, destroy, cec.connection);

	pthread_cancel(device_thread);
	pthread_join(device_thread, NULL);
	pthread_cancel(sq_thread);
	pthread_join(sq_thread, NULL);

	cond_destroy(cec.cond_cec);
	cond_destroy(cec.cond_sq);
	mutex_destroy(cec.mutex);
	cec_queue_flush(&cec.queue);
}

#endif //#if HDMICEC
