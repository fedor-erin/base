#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "tools.h"

using namespace std;

int main(int argc, char **argv)
{

	Authorization aut(0);
	aut.authorizate();
	
	if (aut.check())
                printf("Good\n");
        else
                printf("Bad\n");
	
	return 0;
}
