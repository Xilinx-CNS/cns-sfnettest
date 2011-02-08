#include "sfnettest.h"


void sfnt_abort(void)
{
  abort();
}


void sfnt_fail_test(void)
{
  sfnt_err("ERROR: Test failed.\n");
  abort();
}
