/**************************************************************************
 * Simple Webserver port from pc to Xbox 360 by Quadrant2005  2021
 *
 **************************************************************************/ 

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <winsockx.h>


#pragma warning(disable:4761) //[QBS]


#ifndef	INADDR_NONE
#define	INADDR_NONE	0xffffffff
#endif	/* INADDR_NONE */

void	errexit(const char *, ...);


void	errexit(const char *, ...);

u_short	portbase = 0;		/* port base, for test servers		*/



/*------------------------------------------------------------------------
 * errexit - print an error message and exit
 *------------------------------------------------------------------------
 */
/*VARARGS1*/
void
errexit(const char *format, ...)
{
	va_list	args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	WSACleanup();
	exit(1);
}
