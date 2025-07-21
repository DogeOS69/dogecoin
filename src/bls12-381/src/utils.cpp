#include <bls12-381/utils.hpp>

int qcountl_zero(uint64_t num)
{
    int count = 0;
    for (int i = 63; i >= 0; --i)
    {
        if ((num & (1ULL << i)) == 0)
        {
            count++;
        }
        else
        {
            break;
        }
    }
    return count;
}
