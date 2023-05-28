#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "Json.h"
#include "Exceptions.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();

    try
    {
        openshot::stringToJson(str);
    }
    catch (openshot::InvalidJSON e)
    {
    }
    return 0;
}
