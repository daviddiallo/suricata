#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>

void *ModbusGetTx(void *alstate, uint64_t tx_id);

// Suricata includes
#include "suricata-common.h"

#include "util-debug.h"
#include "util-byte.h"
#include "util-enum.h"
#include "util-mem.h"
#include "util-misc.h"

#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-modbus.h"
#include "app-layer-dns-udp.h"

#include "app-layer-detect-proto.h"

#include "conf.h"
#include "decode.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"

#include "flow-util.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"


intmax_t max_pending_packets;

int afl_dns(uint8_t* buffer, int size){
    int result = 0;
    Flow *f = NULL;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 53);
    if (f == NULL)
        goto end;
    f->proto = IPPROTO_UDP;
    f->alproto = ALPROTO_DNS;
    f->alstate = DNSStateAlloc();

    int DNSUDPResponseParse(Flow *f, void *dstate, AppLayerParserState *pstate, uint8_t *input, uint32_t input_len, void *local_data);
    int r = DNSUDPResponseParse(f, f->alstate, NULL, buffer, size, NULL);
    if (r != 1)
        goto end;

    result = 1;
end:
    UTHFreeFlow(f);
    return (result);
}


int afl_modbus(uint8_t* buffer, int size){
  AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
  Flow f;
  TcpSession ssn;

  memset(&f, 0, sizeof(f));
  memset(&ssn, 0, sizeof(ssn));

  f.protoctx  = (void *)&ssn;
  f.proto     = IPPROTO_TCP;

  StreamTcpInitConfig(TRUE);

  SCMutexLock(&f.m);
  int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOSERVER, buffer, size);

  if (r != 0) {
      printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
      SCMutexUnlock(&f.m);
      return -1;
  }
  SCMutexUnlock(&f.m);

  ModbusState    *modbus_state = f.alstate;
  if (modbus_state == NULL) {
      printf("no modbus state =(\n");
      return -1;
  }
  else
  {
   printf("Got a modbus state !\n");
   ModbusTransaction *tx = ModbusGetTx(modbus_state, 0);
   //printf("%d\n", tx->function);
  }
  return 0;
}


int main(int argc, char **argv)
{
  printf("Hello suricata !\n");

  // Get the size of the file
  struct stat file_stat;
  int ret = stat(argv[1], &file_stat);
  if (ret != 0)
  {
    printf("Can't stat %s !\n", argv[1]);
    return -1;
  }
  int size = file_stat.st_size;
    
  // Read the content of the file;
  FILE *file = fopen(argv[1], "r");
  uint8_t *buffer = (uint8_t*) malloc(size*sizeof(uint8_t));
  int got_size = fread(buffer, 1, size, file);

  if (size != got_size)
  {
    printf("Only got %d bytes instead of %d !\n", got_size, size);
    return -1;
  }

    ConfInit(); // small function
    GlobalInits(); // small function
    TimeInit(); // small function

    void SupportFastPatternForSigMatchTypes();
    SupportFastPatternForSigMatchTypes();

    MpmTableSetup();

    int AppLayerSetup(void);
    AppLayerSetup();

    void RegisterAllModules();
    //RegisterAllModules(); // big function, likely containing useless calls

    //ConfDump();
    
    //afl_modbus(buffer, size);
    afl_dns(buffer, size);

}
