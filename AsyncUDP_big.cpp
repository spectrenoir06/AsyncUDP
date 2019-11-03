#include "Arduino.h"
#include "AsyncUDP_big.h"

extern "C" {
#include "lwip/opt.h"
#include "lwip/inet.h"
#include "lwip/udp.h"
#include "lwip/igmp.h"
#include "lwip/ip_addr.h"
#include "lwip/mld6.h"
#include "lwip/prot/ethernet.h"
#include <esp_err.h>
#include <esp_wifi.h>
}

#include "lwip/priv/tcpip_priv.h"

typedef struct {
    struct tcpip_api_call_data call;
    udp_pcb * pcb;
    const ip_addr_t *addr;
    uint16_t port;
    struct pbuf *pb;
    struct netif *netif;
    err_t err;
} udp_api_call_t;

static err_t _udp_connect_api(struct tcpip_api_call_data *api_call_msg){
    udp_api_call_t * msg = (udp_api_call_t *)api_call_msg;
    msg->err = udp_connect(msg->pcb, msg->addr, msg->port);
    return msg->err;
}

static err_t _udp_connect(struct udp_pcb *pcb, const ip_addr_t *addr, u16_t port){
    udp_api_call_t msg;
    msg.pcb = pcb;
    msg.addr = addr;
    msg.port = port;
    tcpip_api_call(_udp_connect_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

static err_t _udp_disconnect_api(struct tcpip_api_call_data *api_call_msg){
    udp_api_call_t * msg = (udp_api_call_t *)api_call_msg;
    msg->err = 0;
    udp_disconnect(msg->pcb);
    return msg->err;
}

static void  _udp_disconnect(struct udp_pcb *pcb){
    udp_api_call_t msg;
    msg.pcb = pcb;
    tcpip_api_call(_udp_disconnect_api, (struct tcpip_api_call_data*)&msg);
}

static err_t _udp_remove_api(struct tcpip_api_call_data *api_call_msg){
    udp_api_call_t * msg = (udp_api_call_t *)api_call_msg;
    msg->err = 0;
    udp_remove(msg->pcb);
    return msg->err;
}

static void  _udp_remove(struct udp_pcb *pcb){
    udp_api_call_t msg;
    msg.pcb = pcb;
    tcpip_api_call(_udp_remove_api, (struct tcpip_api_call_data*)&msg);
}

static err_t _udp_bind_api(struct tcpip_api_call_data *api_call_msg){
    udp_api_call_t * msg = (udp_api_call_t *)api_call_msg;
    msg->err = udp_bind(msg->pcb, msg->addr, msg->port);
    return msg->err;
}

static err_t _udp_bind(struct udp_pcb *pcb, const ip_addr_t *addr, u16_t port){
    udp_api_call_t msg;
    msg.pcb = pcb;
    msg.addr = addr;
    msg.port = port;
    tcpip_api_call(_udp_bind_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

static err_t _udp_sendto_api(struct tcpip_api_call_data *api_call_msg){
    udp_api_call_t * msg = (udp_api_call_t *)api_call_msg;
    msg->err = udp_sendto(msg->pcb, msg->pb, msg->addr, msg->port);
    return msg->err;
}

static err_t _udp_sendto(struct udp_pcb *pcb, struct pbuf *pb, const ip_addr_t *addr, u16_t port){
    udp_api_call_t msg;
    msg.pcb = pcb;
    msg.addr = addr;
    msg.port = port;
    msg.pb = pb;
    tcpip_api_call(_udp_sendto_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

static err_t _udp_sendto_if_api(struct tcpip_api_call_data *api_call_msg){
    udp_api_call_t * msg = (udp_api_call_t *)api_call_msg;
    msg->err = udp_sendto_if(msg->pcb, msg->pb, msg->addr, msg->port, msg->netif);
    return msg->err;
}

static err_t _udp_sendto_if(struct udp_pcb *pcb, struct pbuf *pb, const ip_addr_t *addr, u16_t port, struct netif *netif){
    udp_api_call_t msg;
    msg.pcb = pcb;
    msg.addr = addr;
    msg.port = port;
    msg.pb = pb;
    msg.netif = netif;
    tcpip_api_call(_udp_sendto_if_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

typedef struct {
        void *arg;
        udp_pcb *pcb;
        pbuf *pb;
        const ip_addr_t *addr;
        uint16_t port;
        struct netif * netif;
} lwip_event_packet_t;

static xQueueHandle _udp_queue;
static volatile TaskHandle_t _udp_task_handle = NULL;

static void _udp_task(void *pvParameters){
    lwip_event_packet_t * e = NULL;
    for (;;) {
        if(xQueueReceive(_udp_queue, &e, portMAX_DELAY) == pdTRUE){
            if(!e->pb){
                free((void*)(e));
                continue;
            }
            AsyncUDP_big_recv(e->arg, e->pcb, e->pb, e->addr, e->port, e->netif);
            free((void*)(e));
        }
    }
    _udp_task_handle = NULL;
    vTaskDelete(NULL);
}

static bool _udp_task_start(){
    if(!_udp_queue){
        _udp_queue = xQueueCreate(32, sizeof(lwip_event_packet_t *));
        if(!_udp_queue){
            return false;
        }
    }
    if(!_udp_task_handle){
        xTaskCreateUniversal(_udp_task, "async_udp", 8160, NULL, 3, (TaskHandle_t*)&_udp_task_handle, CONFIG_ARDUINO_UDP_RUNNING_CORE);
        if(!_udp_task_handle){
            return false;
        }
    }
    return true;
}

static bool _udp_task_post(void *arg, udp_pcb *pcb, pbuf *pb, const ip_addr_t *addr, uint16_t port, struct netif *netif)
{
    if(!_udp_task_handle || !_udp_queue){
        return false;
    }
    lwip_event_packet_t * e = (lwip_event_packet_t *)malloc(sizeof(lwip_event_packet_t));
    if(!e){
        return false;
    }
    e->arg = arg;
    e->pcb = pcb;
    e->pb = pb;
    e->addr = addr;
    e->port = port;
    e->netif = netif;
    if (xQueueSend(_udp_queue, &e, portMAX_DELAY) != pdPASS) {
        free((void*)(e));
        return false;
    }
    return true;
}

static void _udp_recv(void *arg, udp_pcb *pcb, pbuf *pb, const ip_addr_t *addr, uint16_t port)
{
    while(pb != NULL) {
        pbuf * this_pb = pb;
        pb = pb->next;
        this_pb->next = NULL;
        if(!_udp_task_post(arg, pcb, this_pb, addr, port, ip_current_input_netif())){
            pbuf_free(this_pb);
        }
    }
}
/*
static bool _udp_task_stop(){
    if(!_udp_task_post(NULL, NULL, NULL, NULL, 0, NULL)){
        return false;
    }
    while(_udp_task_handle){
        vTaskDelay(10);
    }

    lwip_event_packet_t * e;
    while (xQueueReceive(_udp_queue, &e, 0) == pdTRUE) {
        if(e->pb){
            pbuf_free(e->pb);
        }
        free((void*)(e));
    }
    vQueueDelete(_udp_queue);
    _udp_queue = NULL;
}
*/



#define UDP_MUTEX_LOCK()    //xSemaphoreTake(_lock, portMAX_DELAY)
#define UDP_MUTEX_UNLOCK()  //xSemaphoreGive(_lock)


AsyncUDP_bigage::AsyncUDP_bigage(size_t size)
{
    _index = 0;
    if(size > CONFIG_TCP_MSS) {
        size = CONFIG_TCP_MSS;
    }
    _size = size;
    _buffer = (uint8_t *)malloc(size);
}

AsyncUDP_bigage::~AsyncUDP_bigage()
{
    if(_buffer) {
        free(_buffer);
    }
}

size_t AsyncUDP_bigage::write(const uint8_t *data, size_t len)
{
    if(_buffer == NULL) {
        return 0;
    }
    size_t s = space();
    if(len > s) {
        len = s;
    }
    memcpy(_buffer + _index, data, len);
    _index += len;
    return len;
}

size_t AsyncUDP_bigage::write(uint8_t data)
{
    return write(&data, 1);
}

size_t AsyncUDP_bigage::space()
{
    if(_buffer == NULL) {
        return 0;
    }
    return _size - _index;
}

uint8_t * AsyncUDP_bigage::data()
{
    return _buffer;
}

size_t AsyncUDP_bigage::length()
{
    return _index;
}

void AsyncUDP_bigage::flush()
{
    _index = 0;
}


AsyncUDP_biget::AsyncUDP_biget(AsyncUDP_bigp, pbuf *pb, const ip_addr_t *raddr, uint16_t rport, struct netif * ntif)
{
    _udp = udp;
    _pb = pb;
    _if = TCPIP_ADAPTER_IF_MAX;
    _data = (uint8_t*)(pb->payload);
    _len = pb->len;
    _index = 0;

    pbuf_ref(_pb);

    //memcpy(&_remoteIp, raddr, sizeof(ip_addr_t));
    _remoteIp.type = raddr->type;
    _localIp.type = _remoteIp.type;

    eth_hdr* eth = NULL;
    udp_hdr* udphdr = reinterpret_cast<udp_hdr*>(_data - UDP_HLEN);
    _localPort = ntohs(udphdr->dest);
    _remotePort = ntohs(udphdr->src);

    if (_remoteIp.type == IPADDR_TYPE_V4) {
        eth = (eth_hdr *)(((uint8_t *)(pb->payload)) - UDP_HLEN - IP_HLEN - SIZEOF_ETH_HDR);
        struct ip_hdr * iphdr = (struct ip_hdr *)(((uint8_t *)(pb->payload)) - UDP_HLEN - IP_HLEN);
        _localIp.u_addr.ip4.addr = iphdr->dest.addr;
        _remoteIp.u_addr.ip4.addr = iphdr->src.addr;
    } else {
        eth = (eth_hdr *)(((uint8_t *)(pb->payload)) - UDP_HLEN - IP6_HLEN - SIZEOF_ETH_HDR);
        struct ip6_hdr * ip6hdr = (struct ip6_hdr *)(((uint8_t *)(pb->payload)) - UDP_HLEN - IP6_HLEN);
        memcpy(&_localIp.u_addr.ip6.addr, (uint8_t *)ip6hdr->dest.addr, 16);
        memcpy(&_remoteIp.u_addr.ip6.addr, (uint8_t *)ip6hdr->src.addr, 16);
    }
    memcpy(_remoteMac, eth->src.addr, 6);

    struct netif * netif = NULL;
    void * nif = NULL;
    int i;
    for (i=0; i<TCPIP_ADAPTER_IF_MAX; i++) {
        tcpip_adapter_get_netif ((tcpip_adapter_if_t)i, &nif);
        netif = (struct netif *)nif;
        if (netif && netif == ntif) {
            _if = (tcpip_adapter_if_t)i;
            break;
        }
    }
}

AsyncUDP_biget::~AsyncUDP_biget()
{
    pbuf_free(_pb);
}

uint8_t * AsyncUDP_biget::data()
{
    return _data;
}

size_t AsyncUDP_biget::length()
{
    return _len;
}

int AsyncUDP_biget::available(){
    return _len - _index;
}

size_t AsyncUDP_biget::read(uint8_t *data, size_t len){
    size_t i;
    size_t a = _len - _index;
    if(len > a){
        len = a;
    }
    for(i=0;i<len;i++){
        data[i] = read();
    }
    return len;
}

int AsyncUDP_biget::read(){
    if(_index < _len){
        return _data[_index++];
    }
    return -1;
}

int AsyncUDP_biget::peek(){
    if(_index < _len){
        return _data[_index];
    }
    return -1;
}

void AsyncUDP_biget::flush(){
    _index = _len;
}

tcpip_adapter_if_t AsyncUDP_biget::interface()
{
    return _if;
}

IPAddress AsyncUDP_biget::localIP()
{
    if(_localIp.type != IPADDR_TYPE_V4){
        return IPAddress();
    }
    return IPAddress(_localIp.u_addr.ip4.addr);
}

IPv6Address AsyncUDP_biget::localIPv6()
{
    if(_localIp.type != IPADDR_TYPE_V6){
        return IPv6Address();
    }
    return IPv6Address(_localIp.u_addr.ip6.addr);
}

uint16_t AsyncUDP_biget::localPort()
{
    return _localPort;
}

IPAddress AsyncUDP_biget::remoteIP()
{
    if(_remoteIp.type != IPADDR_TYPE_V4){
        return IPAddress();
    }
    return IPAddress(_remoteIp.u_addr.ip4.addr);
}

IPv6Address AsyncUDP_biget::remoteIPv6()
{
    if(_remoteIp.type != IPADDR_TYPE_V6){
        return IPv6Address();
    }
    return IPv6Address(_remoteIp.u_addr.ip6.addr);
}

uint16_t AsyncUDP_biget::remotePort()
{
    return _remotePort;
}

void AsyncUDP_biget::remoteMac(uint8_t * mac)
{
    memcpy(mac, _remoteMac, 6);
}

bool AsyncUDP_biget::isIPv6()
{
    return _localIp.type == IPADDR_TYPE_V6;
}

bool AsyncUDP_biget::isBroadcast()
{
    if(_localIp.type == IPADDR_TYPE_V6){
        return false;
    }
    uint32_t ip = _localIp.u_addr.ip4.addr;
    return ip == 0xFFFFFFFF || ip == 0 || (ip & 0xFF000000) == 0xFF000000;
}

bool AsyncUDP_biget::isMulticast()
{
    return ip_addr_ismulticast(&(_localIp));
}

size_t AsyncUDP_biget::write(const uint8_t *data, size_t len)
{
    if(!data){
        return 0;
    }
    return _udp->writeTo(data, len, &_remoteIp, _remotePort, _if);
}

size_t AsyncUDP_biget::write(uint8_t data)
{
    return write(&data, 1);
}

size_t AsyncUDP_biget::send(AsyncUDP_bigage &message)
{
    return write(message.data(), message.length());
}

bool AsyncUDP_bignit(){
    if(_pcb){
        return true;
    }
    _pcb = udp_new();
    if(!_pcb){
        return false;
    }
    //_lock = xSemaphoreCreateMutex();
    udp_recv(_pcb, &_udp_recv, (void *) this);
    return true;
}

AsyncUDP_bigyncUDP_big
    _pcb = NULL;
    _connected = false;
    _handler = NULL;
}

AsyncUDP_bigsyncUDP_big
    close();
    UDP_MUTEX_LOCK();
    udp_recv(_pcb, NULL, NULL);
    _udp_remove(_pcb);
    _pcb = NULL;
    UDP_MUTEX_UNLOCK();
    //vSemaphoreDelete(_lock);
}

void AsyncUDP_bigose()
{
    UDP_MUTEX_LOCK();
    if(_pcb != NULL) {
        if(_connected) {
            _udp_disconnect(_pcb);
        }
        _connected = false;
        //todo: unjoin multicast group
    }
    UDP_MUTEX_UNLOCK();
}

bool AsyncUDP_bignnect(const ip_addr_t *addr, uint16_t port)
{
    if(!_udp_task_start()){
        log_e("failed to start task");
        return false;
    }
    if(!_init()) {
        return false;
    }
    close();
    UDP_MUTEX_LOCK();
    err_t err = _udp_connect(_pcb, addr, port);
    if(err != ERR_OK) {
        UDP_MUTEX_UNLOCK();
        return false;
    }
    _connected = true;
    UDP_MUTEX_UNLOCK();
    return true;
}

bool AsyncUDP_bigsten(const ip_addr_t *addr, uint16_t port)
{
    if(!_udp_task_start()){
        log_e("failed to start task");
        return false;
    }
    if(!_init()) {
        return false;
    }
    close();
    if(addr){
        IP_SET_TYPE_VAL(_pcb->local_ip,  addr->type);
        IP_SET_TYPE_VAL(_pcb->remote_ip, addr->type);
    }
    UDP_MUTEX_LOCK();
    if(_udp_bind(_pcb, addr, port) != ERR_OK) {
        UDP_MUTEX_UNLOCK();
        return false;
    }
    _connected = true;
    UDP_MUTEX_UNLOCK();
    return true;
}

static esp_err_t joinMulticastGroup(const ip_addr_t *addr, bool join, tcpip_adapter_if_t tcpip_if=TCPIP_ADAPTER_IF_MAX)
{
    struct netif * netif = NULL;
    if(tcpip_if < TCPIP_ADAPTER_IF_MAX){
        void * nif = NULL;
        esp_err_t err = tcpip_adapter_get_netif(tcpip_if, &nif);
        if (err) {
            return ESP_ERR_INVALID_ARG;
        }
        netif = (struct netif *)nif;

        if (addr->type == IPADDR_TYPE_V4) {
            if(join){
                if (igmp_joingroup_netif(netif, (const ip4_addr *)&(addr->u_addr.ip4))) {
                    return ESP_ERR_INVALID_STATE;
                }
            } else {
                if (igmp_leavegroup_netif(netif, (const ip4_addr *)&(addr->u_addr.ip4))) {
                    return ESP_ERR_INVALID_STATE;
                }
            }
        } else {
            if(join){
                if (mld6_joingroup_netif(netif, &(addr->u_addr.ip6))) {
                    return ESP_ERR_INVALID_STATE;
                }
            } else {
                if (mld6_leavegroup_netif(netif, &(addr->u_addr.ip6))) {
                    return ESP_ERR_INVALID_STATE;
                }
            }
        }
    }  else {
        if (addr->type == IPADDR_TYPE_V4) {
            if(join){
                if (igmp_joingroup((const ip4_addr *)IP4_ADDR_ANY, (const ip4_addr *)&(addr->u_addr.ip4))) {
                    return ESP_ERR_INVALID_STATE;
                }
            } else {
                if (igmp_leavegroup((const ip4_addr *)IP4_ADDR_ANY, (const ip4_addr *)&(addr->u_addr.ip4))) {
                    return ESP_ERR_INVALID_STATE;
                }
            }
        } else {
            if(join){
                if (mld6_joingroup((const ip6_addr *)IP6_ADDR_ANY, &(addr->u_addr.ip6))) {
                    return ESP_ERR_INVALID_STATE;
                }
            } else {
                if (mld6_leavegroup((const ip6_addr *)IP6_ADDR_ANY, &(addr->u_addr.ip6))) {
                    return ESP_ERR_INVALID_STATE;
                }
            }
        }
    }
    return ESP_OK;
}

bool AsyncUDP_bigstenMulticast(const ip_addr_t *addr, uint16_t port, uint8_t ttl, tcpip_adapter_if_t tcpip_if)
{
    if(!ip_addr_ismulticast(addr)) {
        return false;
    }

    if (joinMulticastGroup(addr, true, tcpip_if)!= ERR_OK) {
        return false;
    }

    if(!listen(NULL, port)) {
        return false;
    }

    UDP_MUTEX_LOCK();
    _pcb->mcast_ttl = ttl;
    _pcb->remote_port = port;
    ip_addr_copy(_pcb->remote_ip, *addr);
    //ip_addr_copy(_pcb->remote_ip, ip_addr_any_type);
    UDP_MUTEX_UNLOCK();

    return true;
}

size_t AsyncUDP_bigiteTo(const uint8_t * data, size_t len, const ip_addr_t * addr, uint16_t port, tcpip_adapter_if_t tcpip_if)
{
    if(!_pcb) {
        UDP_MUTEX_LOCK();
        _pcb = udp_new();
        UDP_MUTEX_UNLOCK();
        if(_pcb == NULL) {
            return 0;
        }
    }
    if(len > CONFIG_TCP_MSS) {
        len = CONFIG_TCP_MSS;
    }
    err_t err = ERR_OK;
    pbuf* pbt = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if(pbt != NULL) {
        uint8_t* dst = reinterpret_cast<uint8_t*>(pbt->payload);
        memcpy(dst, data, len);
        UDP_MUTEX_LOCK();
        if(tcpip_if < TCPIP_ADAPTER_IF_MAX){
            void * nif = NULL;
            tcpip_adapter_get_netif((tcpip_adapter_if_t)tcpip_if, &nif);
            if(!nif){
                err = _udp_sendto(_pcb, pbt, addr, port);
            } else {
                err = _udp_sendto_if(_pcb, pbt, addr, port, (struct netif *)nif);
            }
        } else {
            err = _udp_sendto(_pcb, pbt, addr, port);
        }
        UDP_MUTEX_UNLOCK();
        pbuf_free(pbt);
        if(err < ERR_OK) {
            return 0;
        }
        return len;
    }
    return 0;
}

void AsyncUDP_bigecv(udp_pcb *upcb, pbuf *pb, const ip_addr_t *addr, uint16_t port, struct netif * netif)
{
    while(pb != NULL) {
        pbuf * this_pb = pb;
        pb = pb->next;
        this_pb->next = NULL;
        if(_handler) {
            AsyncUDP_biget packet(this, this_pb, addr, port, netif);
            _handler(packet);
        } else {
            pbuf_free(this_pb);
        }
    }
}

void AsyncUDP_big_recv(void *arg, udp_pcb *upcb, pbuf *p, const ip_addr_t *addr, uint16_t port, struct netif * netif)
{
    reinterpret_cast<AsyncUDP_bigrg)->_recv(upcb, p, addr, port, netif);
}

bool AsyncUDP_bigsten(uint16_t port)
{
    return listen(IP_ANY_TYPE, port);
}

bool AsyncUDP_bigsten(const IPAddress addr, uint16_t port)
{
    ip_addr_t laddr;
    laddr.type = IPADDR_TYPE_V4;
    laddr.u_addr.ip4.addr = addr;
    return listen(&laddr, port);
}

bool AsyncUDP_bigstenMulticast(const IPAddress addr, uint16_t port, uint8_t ttl, tcpip_adapter_if_t tcpip_if)
{
    ip_addr_t laddr;
    laddr.type = IPADDR_TYPE_V4;
    laddr.u_addr.ip4.addr = addr;
    return listenMulticast(&laddr, port, ttl, tcpip_if);
}

bool AsyncUDP_bignnect(const IPAddress addr, uint16_t port)
{
    ip_addr_t daddr;
    daddr.type = IPADDR_TYPE_V4;
    daddr.u_addr.ip4.addr = addr;
    return connect(&daddr, port);
}

size_t AsyncUDP_bigiteTo(const uint8_t *data, size_t len, const IPAddress addr, uint16_t port, tcpip_adapter_if_t tcpip_if)
{
    ip_addr_t daddr;
    daddr.type = IPADDR_TYPE_V4;
    daddr.u_addr.ip4.addr = addr;
    return writeTo(data, len, &daddr, port, tcpip_if);
}

IPAddress AsyncUDP_bigstenIP()
{
    if(!_pcb || _pcb->remote_ip.type != IPADDR_TYPE_V4){
        return IPAddress();
    }
    return IPAddress(_pcb->remote_ip.u_addr.ip4.addr);
}

bool AsyncUDP_bigsten(const IPv6Address addr, uint16_t port)
{
    ip_addr_t laddr;
    laddr.type = IPADDR_TYPE_V6;
    memcpy((uint8_t*)(laddr.u_addr.ip6.addr), (const uint8_t*)addr, 16);
    return listen(&laddr, port);
}

bool AsyncUDP_bigstenMulticast(const IPv6Address addr, uint16_t port, uint8_t ttl, tcpip_adapter_if_t tcpip_if)
{
    ip_addr_t laddr;
    laddr.type = IPADDR_TYPE_V6;
    memcpy((uint8_t*)(laddr.u_addr.ip6.addr), (const uint8_t*)addr, 16);
    return listenMulticast(&laddr, port, ttl, tcpip_if);
}

bool AsyncUDP_bignnect(const IPv6Address addr, uint16_t port)
{
    ip_addr_t daddr;
    daddr.type = IPADDR_TYPE_V6;
    memcpy((uint8_t*)(daddr.u_addr.ip6.addr), (const uint8_t*)addr, 16);
    return connect(&daddr, port);
}

size_t AsyncUDP_bigiteTo(const uint8_t *data, size_t len, const IPv6Address addr, uint16_t port, tcpip_adapter_if_t tcpip_if)
{
    ip_addr_t daddr;
    daddr.type = IPADDR_TYPE_V6;
    memcpy((uint8_t*)(daddr.u_addr.ip6.addr), (const uint8_t*)addr, 16);
    return writeTo(data, len, &daddr, port, tcpip_if);
}

IPv6Address AsyncUDP_bigstenIPv6()
{
    if(!_pcb || _pcb->remote_ip.type != IPADDR_TYPE_V6){
        return IPv6Address();
    }
    return IPv6Address(_pcb->remote_ip.u_addr.ip6.addr);
}

size_t AsyncUDP_bigite(const uint8_t *data, size_t len)
{
    return writeTo(data, len, &(_pcb->remote_ip), _pcb->remote_port);
}

size_t AsyncUDP_bigite(uint8_t data)
{
    return write(&data, 1);
}

size_t AsyncUDP_bigoadcastTo(uint8_t *data, size_t len, uint16_t port, tcpip_adapter_if_t tcpip_if)
{
    return writeTo(data, len, IP_ADDR_BROADCAST, port, tcpip_if);
}

size_t AsyncUDP_bigoadcastTo(const char * data, uint16_t port, tcpip_adapter_if_t tcpip_if)
{
    return broadcastTo((uint8_t *)data, strlen(data), port, tcpip_if);
}

size_t AsyncUDP_bigoadcast(uint8_t *data, size_t len)
{
    if(_pcb->local_port != 0) {
        return broadcastTo(data, len, _pcb->local_port);
    }
    return 0;
}

size_t AsyncUDP_bigoadcast(const char * data)
{
    return broadcast((uint8_t *)data, strlen(data));
}


size_t AsyncUDP_bigndTo(AsyncUDP_bigage &message, const ip_addr_t *addr, uint16_t port, tcpip_adapter_if_t tcpip_if)
{
    if(!message) {
        return 0;
    }
    return writeTo(message.data(), message.length(), addr, port, tcpip_if);
}

size_t AsyncUDP_bigndTo(AsyncUDP_bigage &message, const IPAddress addr, uint16_t port, tcpip_adapter_if_t tcpip_if)
{
    if(!message) {
        return 0;
    }
    return writeTo(message.data(), message.length(), addr, port, tcpip_if);
}

size_t AsyncUDP_bigndTo(AsyncUDP_bigage &message, const IPv6Address addr, uint16_t port, tcpip_adapter_if_t tcpip_if)
{
    if(!message) {
        return 0;
    }
    return writeTo(message.data(), message.length(), addr, port, tcpip_if);
}

size_t AsyncUDP_bignd(AsyncUDP_bigage &message)
{
    if(!message) {
        return 0;
    }
    return writeTo(message.data(), message.length(), &(_pcb->remote_ip), _pcb->remote_port);
}

size_t AsyncUDP_bigoadcastTo(AsyncUDP_bigage &message, uint16_t port, tcpip_adapter_if_t tcpip_if)
{
    if(!message) {
        return 0;
    }
    return broadcastTo(message.data(), message.length(), port, tcpip_if);
}

size_t AsyncUDP_bigoadcast(AsyncUDP_bigage &message)
{
    if(!message) {
        return 0;
    }
    return broadcast(message.data(), message.length());
}

AsyncUDP_bigerator bool()
{
    return _connected;
}

bool AsyncUDP_bignnected()
{
    return _connected;
}

void AsyncUDP_bigPacket(AuPacketHandlerFunctionWithArg cb, void * arg)
{
    onPacket(std::bind(cb, arg, std::placeholders::_1));
}

void AsyncUDP_bigPacket(AuPacketHandlerFunction cb)
{
    _handler = cb;
}
