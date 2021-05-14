//--------------------------------------------------------------------------------------
//[QBS]Quadrant i took SimpleSocket sample project from xbox xdk gutted out the main function replacing
// it with my html server as i do not yet know how to create projects from scratch on xbox360
//I used Release_LTCG
// Used with MSVC 2010
//--------------------------------------------------------------------------------------
#include <xtl.h>
#include <xbdm.h>
#include <malloc.h>
#include <stdio.h>
#include <winsockx.h>

#include "AtgConsole.h"
#include "AtgInput.h"
#include "AtgUtil.h"

#include "X360WebServer.h"//[QBS]


#include <malloc.h>


#include <xonline.h>
#include <xaudio2.h>
#include <xhv2.h>

#include <process.h>
#include <stdlib.h>
#include <string.h>

// use stl to manage remote console data
#include <list> 
#include <set>

#pragma warning(disable:4127 4244 4702 4996)   // we use some infinite loops, disable "conditional expression constant" warning

//--------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------
const UINT      NONCE_SIZE = 8;    // 8-byte nonce for recognition of 
// broadcast return
const UINT      MAX_DATA_SIZE = 64;   // maximum length of string data to send
const UINT      MIN_DATA_SIZE = 8;    // minimum length of string data to send
const DWORD     MSG_FREQ_IN_MS = 1000; // time (in ms) between messages
const UINT      MAX_SEEK_RETRY = 5;    // number of times to seek before giving 
// up and hosting

const USHORT    PORT_NUM = 1000;   // For maximum efficiency, all Xbox network 
// traffic should be on port 1000


//--------------------------------------------------------------------------------------
// Message IDs
//--------------------------------------------------------------------------------------
enum MessageID
{
    MessageID_Seeking,    // broadcast: looking for a host
    MessageID_Found,      // broadcast: response to a SEEKING message
    MessageID_Data        // data message, demonstrating communication
};

struct SMessage
{
    MessageID m_id;
};

struct SSeekingMessage : public SMessage
{
    BYTE m_Nonce[NONCE_SIZE];  // the nonce is used so we recognize a reply
};

struct SFoundMessage : public SMessage
{
    BYTE m_Nonce[NONCE_SIZE];   // nonce of the sender of the seeking message
    XNADDR m_xnaddr;              // XNADDR of the host
    XNKID m_xnkid;               // Key ID to use for secure communication
    XNKEY m_xnkey;               // Key to use for secure communication
};

struct SDataMessage : public SMessage
{
    UINT m_uiSequenceNumber;           // integer data
    SIZE_T m_size;                       // message size (for verification)
    CHAR            m_strData[MAX_DATA_SIZE + 1]; // string data (variable length)

    inline SIZE_T   GetSize()
    {
        return
            sizeof( m_id ) +
            sizeof( m_uiSequenceNumber ) +
            sizeof( m_size ) +
            strlen( m_strData ) + 1;
    }
};

union UMessage
{
    SMessage m_Message;
    SSeekingMessage m_Seeking;
    SFoundMessage m_Found;
    SDataMessage m_Data;
};


//--------------------------------------------------------------------------------------
// Globals
//--------------------------------------------------------------------------------------
SOCKET          g_socket;                      // socket we use for transmitting/receiving
XNADDR          g_xnaddr;                      // our own XNADDR
XNKID           g_xnkid;                       // key ID for session
XNKEY           g_xnkey;                       // key for session
DWORD           g_dwLastSend;                  // tick count of last send
IN_ADDR         g_sinPeer;                     // address of our peer
ATG::Console    g_console;                   // console for output
UMessage        g_message;                   // received message


//--------------------------------------------------------------------------------------
// Enumerated types
//--------------------------------------------------------------------------------------
enum SENDMESSAGE_TYPE
{
    SM_PEER         = FALSE,
    SM_BROADCAST    = TRUE
};


//--------------------------------------------------------------------------------------
// Declarations
//--------------------------------------------------------------------------------------
VOID Initialize( VOID );
VOID Shutdown( VOID );

#define		MAX_BUFFER	8096//[qbs]1024			// Maximum buffer size to receive at once.
#define		HTTP_PORT	80				// Port for the webserver...

WSADATA		Data;						// Storage..
SOCKADDR_IN	ServerSockAddr,ClientSockAddr;			// Socket address.
SOCKET		ServerSocket;				// The actual socket.
int			RUNNING;					// Flag that the server is running.

void http_request(void *);				// prototype..

CRITICAL_SECTION serverLock;
void Socket_Bypass()
{
	InitializeCriticalSection(&serverLock);//[QBS] is this for files or for network stuff ??
	XNetStartupParams xnsp;
	memset(&xnsp, 0, sizeof(xnsp));
	xnsp.cfgSizeOfStruct = sizeof(XNetStartupParams);
	xnsp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;
	int err = XNetStartup(&xnsp);

	XNADDR pxna;
	while (XNetGetTitleXnAddr(&pxna) == 0);

	WSADATA wsaData;
	err = WSAStartup(MAKEWORD(2, 2), &wsaData);

	ServerSocket = socket(AF_INET, SOCK_STREAM, 0);

	int setting = 1;
	setsockopt(ServerSocket, SOL_SOCKET, 0x5801, (char*)(&setting), sizeof(int));
}

void print_client_addr(struct sockaddr_in addr)
{
	printf("%d.%d.%d.%d",
		   addr.sin_addr.s_addr & 0xff,
		   (addr.sin_addr.s_addr & 0xff00) >> 8,
		   (addr.sin_addr.s_addr & 0xff0000) >> 16,
		   (addr.sin_addr.s_addr & 0xff000000) >> 24);
}
//--------------------------------------------------------------------------------------
// Main
//
// Main game loop; drive the state machine
//--------------------------------------------------------------------------------------
VOID __cdecl main()
{
	int			status;
	int			count;
	int			addrLen = sizeof(SOCKADDR_IN);
//	SOCKADDR_IN	ClientSockAddr;
	SOCKET	    *ClientSocket;
	DWORD		threadID;
    // Initialize the application
    Initialize();

	printf("\nHttp  WebServer on port: %d\nVersion 1.2 Beta\nBuild: %s Time: %s\n\nCoded By: Quadrant2005\n\n",HTTP_PORT,__DATE__,__TIME__);
	g_console.Format( "\nHttp  WebServer on port: %d\nVersion 1.2 Beta\nBuild: %s Time: %s\n\nCoded By: Quadrant2005\n\n",HTTP_PORT,__DATE__,__TIME__);

	// Init windows sockets:
	status = WSAStartup(MAKEWORD(1, 1), &Data);
	if (status)
	{
		printf("ERROR: WSAStartup didn't work\n");
		g_console.Format( "ERROR: WSAStartup didn't work\n");
	//	exit(1);
	}

	//
	// Init some variables:
	memset(&ServerSockAddr, 0, sizeof(ServerSockAddr));
	count = 0;
	RUNNING = 1;	// Initially running =)

	Socket_Bypass();//[QBS] needs sorting
	EnterCriticalSection(&serverLock);//[QBS] is this for files or for network stuff ??
	// Create the socket:
	ServerSocket = socket(AF_INET, SOCK_STREAM, 0);
	 if( ServerSocket == INVALID_SOCKET )
    {
        ATG::FatalError( "Failed to create socket, error %d.\n", WSAGetLastError() );
    }
	//
	// Setup some socket info:
	SOCKADDR_IN ServerSockAddr;
	ServerSockAddr.sin_port = htons(HTTP_PORT);	// Port of the socket.
	ServerSockAddr.sin_family = AF_INET;		// Socket is "internet" type.
	ServerSockAddr.sin_addr.s_addr = htonl(INADDR_ANY);	// default IP address.

	if (ServerSocket == INVALID_SOCKET)
	{
		printf("ERROR: socket() unsucessful..\n");
		g_console.Format( "ERROR: socket() unsucessful..\n");
		status = WSACleanup();

		if (status == SOCKET_ERROR)
			printf("WSACleanup() failed!\n");
			g_console.Format( "WSACleanup() failed!\n");
			//exit(1);
	}

//[QBS]s26-01-2021
	// after setting these undocumented flags on a socket they should then run unencrypted
	BOOL bBroadcast = TRUE;

	if( setsockopt(ServerSocket, SOL_SOCKET, 0x5802, (PCSTR)&bBroadcast, sizeof(BOOL) ) != 0 )//PATCHED!
	{
		g_console.Format( "Failed to set socket to 5802, error");
//		return 0;
	}

	if( setsockopt(ServerSocket, SOL_SOCKET, 0x5801, (PCSTR)&bBroadcast, sizeof(BOOL) ) != 0 )//PATCHED!
	{
		g_console.Format( "Failed to set socket to 5801, error");
//		return 0;
	}
//[QBS]e26-01-2021
	//
	// Attach the socket to the local machine:
	if (bind(ServerSocket, (LPSOCKADDR) &ServerSockAddr, sizeof(ServerSockAddr)) != 0 )
	 {
 //       ATG::FatalError( "Failed to bind socket, error %d.\n", WSAGetLastError() );
		printf("ERROR: bind() failed!\n");
		g_console.Format( "ERROR: bind() failed!\n");
		status = WSACleanup();
		if (status == SOCKET_ERROR)
		{
			printf("WSACleanup() failed!\n");
			g_console.Format( "WSACleanup() failed!\n");
		}
    }

	// Tell the socket to "listen" for incoming connections!
	status = listen(ServerSocket, 1);

	if (status == SOCKET_ERROR)
	{
		printf("ERROR: listen() failed!\n");
		g_console.Format( "ERROR: listen() failed!\n");

		status = WSACleanup();

		if (status == SOCKET_ERROR)
			printf("WSACleanup() failed!\n");
			g_console.Format( "WSACleanup() failed!\n");

	//	exit(1);
	}

	//
	//[QBS]s26-01-2021
	XNADDR addr;
	XNetGetTitleXnAddr(&addr);
	char ip[16];
	sprintf_s(ip, 16, "%d.%d.%d.%d", (byte)addr.ina.S_un.S_un_b.s_b1,
		(byte)addr.ina.S_un.S_un_b.s_b2,
		(byte)addr.ina.S_un.S_un_b.s_b3,
		(byte)addr.ina.S_un.S_un_b.s_b4
		);

//	g_console.Format("HTTPServer", "XNetGetTitleXnAddr returned %s",ip);
	// Now wait for incoming connections and handle them when needed:
	printf("Html Server started! %s:%i\n",ip,HTTP_PORT);	
	g_console.Format( "Html Server started! %s:%i\n",ip,HTTP_PORT);			
	print_client_addr (ServerSockAddr);//[QBS]17-01-2021 server ip this time lets reuse the function maybe
	printf("------------------------\n");
	g_console.Format( "------------------------\n");

	while (RUNNING)
	{
		// Accept a connection when one comes in. Waits here if no incoming
		// connections are pending:
		ClientSocket = (SOCKET *) malloc(sizeof(SOCKET));

		if (!ClientSocket)
		{
			printf("ERROR: out of memory!\n");
			g_console.Format( "ERROR: out of memory!\n");

			closesocket(ServerSocket);
			status = WSACleanup();

			if (status == SOCKET_ERROR)
				printf("WSACleanup() failed!\n");
				g_console.Format( "WSACleanup() failed!\n");
//			exit(1);
		}

		*ClientSocket = accept(ServerSocket, (LPSOCKADDR) &ClientSockAddr, &addrLen);

//		printf("cl->ip %s\n",inet_ntoa(ClientSockAddr.sin_addr));
//		Log_Printf("cl->ip %s\n",inet_ntoa(ClientSockAddr.sin_addr));
		print_client_addr (ClientSockAddr);//[QBS]17-01-2021

		if (*ClientSocket == INVALID_SOCKET)
		{//[QBS]added
			printf("ERROR: accept() failed!\n");
			g_console.Format( "ERROR: accept() failed!\n");
		}//[QBS]added

		else
		{
			// Otherwise we have a valid connection, so SERVE it!
			threadID = _beginthread(http_request, 0, (VOID *) ClientSocket);
			if (threadID == -1)
			{
				printf("ERROR: _beginthread() failed!\n");
				g_console.Format( "ERROR: _beginthread() failed!\n");

				status = closesocket(*ClientSocket);

				if (status == SOCKET_ERROR)
					printf("ERROR: closesocket() failed!\n");
					g_console.Format( "ERROR: closesocket() failed!\n");

			}

//			sleep(1);
			// Get ready for next request...
			if (ClientSocket)
				ClientSocket = NULL;
		}
	}

	closesocket(ServerSocket);
	status = WSACleanup();

	if (status == SOCKET_ERROR)
		printf("WSACleanup() failed!\n");

	LeaveCriticalSection(&serverLock);//[QBS] is this for files or for network stuff ??

	printf("------------------------\n");
	g_console.Format( "------------------------\n");
	printf("Html Server shutdown.\n");
	g_console.Format( "Html Server shutdown.\n");
    Shutdown();
}



//--------------------------------------------------------------------------------------
// Initialize
//
// Set up SNL and socket
//--------------------------------------------------------------------------------------
VOID Initialize( VOID )
{
    // Initialize the console
    HRESULT hr = g_console.Create( "game:\\Media\\Fonts\\Arial_12.xpr", 0xff0000ff, 0xffffffff );
    if( FAILED( hr ) )
    {
        ATG::FatalError( "Console initialization failed.\n" );
    }

    g_console.Format( "*** INITIALIZING ***\n" );

    // Start up the SNL with default initialization parameters
/*//[QBS]
    if( XNetStartup( NULL ) != 0 )
    {
        ATG::FatalError( "XNetStartup failed.\n" );
    }
	*/
    // Start up Winsock
    WORD wVersion = MAKEWORD( 2, 2 );   // request version 2.2 of Winsock
    WSADATA wsaData;

    INT err = WSAStartup( wVersion, &wsaData );
    if( err != 0 )
    {
        ATG::FatalError( "WSAStartup failed, error %d.\n", err );
    }

    // Verify that we got the right version of Winsock
    if( wsaData.wVersion != wVersion )
    {
        ATG::FatalError( "Failed to get proper version of Winsock, got %d.%d.\n",
                         LOBYTE( wsaData.wVersion ), HIBYTE( wsaData.wVersion ) );
    }
/*
    // Initialize the socket
    g_socket = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
    if( g_socket == INVALID_SOCKET )
    {
        ATG::FatalError( "Failed to create socket, error %d.\n", WSAGetLastError() );
    }

    // Bind the socket
    SOCKADDR_IN sa;
    sa.sin_family = AF_INET;           // IP family
    sa.sin_addr.s_addr = INADDR_ANY;        // Use the only IP that's available to us
    sa.sin_port = htons( PORT_NUM ); // Port (should be 1000)

    if( bind( g_socket, ( const sockaddr* )&sa, sizeof( sa ) ) != 0 )
    {
        ATG::FatalError( "Failed to bind socket, error %d.\n", WSAGetLastError() );
    }

    // Set the socket to nonblocking
    unsigned long iUnblocking = 1;
    if( ioctlsocket( g_socket, FIONBIO, &iUnblocking ) != 0 )
    {
        ATG::FatalError( "Failed to set socket to nonblocking, error %d\n", WSAGetLastError() );
    }

    // Permit the socket to send broadcasts
    BOOL bBroadcast = TRUE;
    if( setsockopt(
        g_socket, SOL_SOCKET, SO_BROADCAST, ( PCSTR )&bBroadcast, sizeof( BOOL ) ) != 0 )
    {
        ATG::FatalError( "Failed to set socket to broadcast-capable, error %d\n",
                         WSAGetLastError() );
    }

    // Get our own XNADDR
    DWORD dwRet;
    do
    {
        dwRet = XNetGetTitleXnAddr( &g_xnaddr );
    } while( dwRet == XNET_GET_XNADDR_PENDING );

    if( dwRet & XNET_GET_XNADDR_NONE )
    {
        ATG::FatalError( "Unable to find an XNADDR.\n" );
    }

    g_console.Format( "XNADDR: %02X:%02X:%02X:%02X:%02X:%02X\n",
                      g_xnaddr.abEnet[0], g_xnaddr.abEnet[1], g_xnaddr.abEnet[2],
                      g_xnaddr.abEnet[3], g_xnaddr.abEnet[4], g_xnaddr.abEnet[5] );
*/
    return;
}


//--------------------------------------------------------------------------------------
// Shutdown
//
// Tear everything down
//--------------------------------------------------------------------------------------
VOID Shutdown( VOID )
{
    g_console.Format( "*** SHUTTING DOWN ***\n" );

    // Close our socket, if any
    if( g_socket != INVALID_SOCKET )
    {
        closesocket( g_socket );
        g_socket = INVALID_SOCKET;
    }

    // Terminate Winsock
    WSACleanup();

    // Terminate the SNL
    XNetCleanup();
    return;
}


//################################################################################

//
// This is the thread function that handles the client's request:
CRITICAL_SECTION fileLock;

void http_request(void *ptr)
{
	char	buf[MAX_BUFFER],
			buf2[MAX_BUFFER];
	int		status,
			count;
	char	tmp,
			*p, 
			*q;
	SOCKET	*ClientSocket = (SOCKET *) ptr;
	FILE	*H;
	int sent_test_page=0;
	int outchars;

	// Init the variables:
	status = count = 0;
	memset(buf, 0, MAX_BUFFER);

	InitializeCriticalSection(&fileLock);//[QBS] XBOX SECURITY FILE ACCESS

	EnterCriticalSection(&fileLock);//[QBS] XBOX SECURITY FILE ACCESS

	// 1st, get the requested filename/path:
	count = recv(*ClientSocket, buf, sizeof(buf), 0);

	if (!count || count == SOCKET_ERROR)
	{
		printf("Connection terminated early\n");
		g_console.Format( "Connection terminated early\n" );

		status = shutdown(*ClientSocket, 2);

		if (status == SOCKET_ERROR)
		{
			printf("Shutdown of client unsuccessful\n");
			g_console.Format( "Shutdown of client unsuccessful\n");
			status = closesocket(*ClientSocket);
		}

		if (status == SOCKET_ERROR)
			printf("closesocket() unsuccessful\n");
			g_console.Format( "closesocket() unsuccessful\n" );

		free(ClientSocket);
		return;
	}
//[QBS]start
	printf("clients details: %s\n", buf);
	g_console.Format( "clients details: %s\n", buf);
//[QBS]end

	// chop at the first newline character for simplicity...
	for (p = buf; p && *p != '\n'; p++);
	
	if (*p == '\n')
		*p = '\0';	// terminate the string early =)

//	printf("request for: %s\n", buf+6);
//	Log_Printf ("request for: %s\n", buf+6);
	printf("request for: %s\n", buf);
	g_console.Format( "request for: %s\n", buf);
//##########TEST########
//		return;
//######################
	//
	// Now ideally here you would check to see what the client accepts
	// and what HTTP protocol version the client is using, but to keep this
	// short, i'm gonna' assume we are using HTTP/1.0
	//
	// A request line should now look like this...
	//
	// "GET /filename HTTP/1.0"
	//
	// So we must chop some junk out of there...
	p = strstr(buf, "GET");

	if (!p)
	{
		printf("Invalid request line %s!\n", buf);
		g_console.Format( "Invalid request line %s!\n", buf);
		closesocket(*ClientSocket);
		free(ClientSocket);
		return;
	}

	p += (strlen("GET") + 1);	// move to the filename

//[QBS]	if (*p == '/')
	if (*p == '/' || *p == '\\' )
		p++;					// we dont want this char either..

	//
	// Ok, now we just have to chop off at the end of the filename:
	q = strstr(p, "HTTP");
/*
	if (!q)
	{
		printf("Invalid request line %s!\n", buf);
		status = shutdown(*ClientSocket, 2);

		if (status == SOCKET_ERROR)
			printf("Shutdown of client unsuccessful\n");
			status = closesocket(*ClientSocket);

		if (status == SOCKET_ERROR)
			printf("closesocket() unsuccessful\n");
			free(ClientSocket);
			return;
	}	
*/
	q--;		// we really wanna' back up one to zap
	*q = '\0';	// the trailing space...

//##########TEST########
//		return;
//######################

	//
	// Now we are ready for busines... so open the file!

	printf("file: %s\n", p);	// uncomment if you wanna' see the filename
	g_console.Format( "file: %s\n", p);
//[QBS] Filter out these extention types

	if (strcmp(q-3,"sys")==0)
	{
		printf ("FILE TYPE NOT ALLOWED\n");
		g_console.Format( "FILE TYPE sys NOT ALLOWED\n");
		return;
	}
	if (strcmp(q-3,"exe")==0)
	{
		printf ("FILE TYPE NOT ALLOWED\n");
		g_console.Format( "FILE TYPE exe NOT ALLOWED\n");
		return;
	}
	if (strcmp(q-3,"xex")==0)
	{
		printf ("FILE TYPE NOT ALLOWED\n");
		g_console.Format( "FILE TYPE xex NOT ALLOWED\n");
		return;
	}
	if (strcmp(q-3,"com")==0)
	{
		printf ("FILE TYPE NOT ALLOWED\n");
		g_console.Format( "FILE TYPE com NOT ALLOWED\n");
		return;
	}
	if (strcmp(q-3,"bat")==0)
	{
		printf ("FILE TYPE NOT ALLOWED\n");
		g_console.Format( "FILE TYPE bat NOT ALLOWED\n");
		return;
	}
	if (strcmp(q-3,"txt")==0)
	{
		printf ("FILE TYPE NOT ALLOWED\n");
		g_console.Format( "FILE TYPE txt NOT ALLOWED\n");
		return;
	}

//##########

outchars = strlen(buf);//get length (includes carriage return)		
//debug info	
	if (outchars)
	{
	printf ("cl->svr [%s] in buf [%d] chars\n",p,outchars-5);
	g_console.Format( "cl->svr [%s] in buf [%d] chars\n",p,outchars-5);
	}

if (strcmp(q-3,"?ip")==0)//works
		{
		 memset(buf, 0, sizeof(buf));

		 XNADDR addr;
	     XNetGetTitleXnAddr(&addr);
	     char serverip[16];
		sprintf_s(serverip, 16, "%d.%d.%d.%d", (byte)addr.ina.S_un.S_un_b.s_b1,
		(byte)addr.ina.S_un.S_un_b.s_b2,
		(byte)addr.ina.S_un.S_un_b.s_b3,
		(byte)addr.ina.S_un.S_un_b.s_b4
		);		

		sprintf_s(buf, "<HTML><HEAD><TITLE>TEST SEND PAGE</TITLE>%s",serverip);

	     send(*ClientSocket, buf, strlen(buf)+1, 0);
		 sent_test_page++;
		 return;
		} 
	  //########
//########
 return;//DISABLE NORMAL HTTP SERVER RESPONSES (Serving files from the xbox still seems to need something adding mmm...
//########
	if (!strlen(p))				// Then we have a request for the "default"
		p = "index.html";		// html file.  This varies from server to
//		p = "Hdd:\\DEMOS\\index.html";		// html file.  This varies from server to
								// server, but I'm gonna' use index.html as
								// my default file.  In a real package this
								// would be yet another option in a config
								// file.
//######START
//Hdd:\\QuadKill\\scripts.rpf
/*
		FILE *fp;
   int c;
   char buffer[1024];
//	EnterCriticalSection(&Read);
   fp = fopen("Hdd:\\logs\\test.txt","r");


   while(1) {
      c = fgetc(fp);
      if( feof(fp) ) 
	  {
         break ;
      }
      printf("%c", c);
   }
  
  */
//#######END


	//FILE* f ;
		//fopen_s(&f,("hdd1:\\demos\\test.png"),"wb");
		//fwrite(buff.GetData(),(size_t)buff.GetDataLength(),1,f);
		
		//fclose(f);

	H = fopen(p, "rb");//read binary

	errno_t err;
	err = fopen_s(&H,p, "rb");//read binary
/*
	 if( err == 0 )
   {
      printf( "The file 'crt_fopen_s.c' was opened\n" );
   }
   else
   {
      printf( "The file 'crt_fopen_s.c' was not opened\n" );
   }*/
   
//	if (!H)
	 if (!err)
	{
		// The file doesn't exist! so warn the client:
		memset(buf2, 0, MAX_BUFFER);
		//
	
//[QBS]
if (!sent_test_page)
	{
	sprintf_s(buf2, "\n<BODY bgColor=#ffffff>\n<TABLE border=0 width=600>\n<TBODY>\n<TR>\n<TD><IMG height=113 src='headbang.gif' width=113></TD><TD><TABLE border=0><TBODY><TR><TD><FONT face='Verdana, Arial, Helvetica, sans-serif' size=5><IMG height=20 src='404Error.gif' width=344></FONT></TD></TR><TR><TD height=25><FONT face='Verdana, Arial, Helvetica, sans-serif' size=2><B>The page (%s) you requested does not exist<BR></B></FONT></TD></TR><TR><TD><FONT face='Verdana, Arial, Helvetica, sans-serif' size=2><B>It may have been renamed or moved or the page's address was mistyped. You should <A href='http://www.quake2.tzo.com/'>go to our Home Page</A> and look for the information you need from there.</B></FONT></TD></TR></TBODY></TABLE></TD></TR></TBODY></TABLE></BODY></HTML>",p);
	sent_test_page=0;
	}
//[QBS]end
		//
		// Now send the data:
		count = send(*ClientSocket, buf2, strlen(buf2)+1, 0);

		if (count != (int)(strlen(buf2)+1))
		{
			printf("Connection terminated.\n");
			g_console.Format( "Connection terminated.\n");
			status = shutdown(*ClientSocket, 2);

			if (status == SOCKET_ERROR)
			{
				printf("Shutdown of client unsuccessful\n");
				g_console.Format( "Shutdown of client unsuccessful\n");
			//
			status = closesocket(*ClientSocket);
			}

			if (status == SOCKET_ERROR)
			{
				printf("closesocket() unsuccessful\n");
				g_console.Format( "closesocket() unsuccessful\n");
			//
			free(ClientSocket);
			}
			//
			return;
		}
	}
	else
	{
		// Now send the data:
		while(!feof(H))
		{
			tmp = fgetc(H);		// Stupid browsers (or protocol?) seem to want
								// their data spoon fed, 1 byte at a time.
			if (!feof(H))
			{
				count = send(*ClientSocket, &tmp, 1, 0);

				if (count != 1)
				{
					printf("Connection terminated.\n");
					g_console.Format( "Connection terminated.\n");
					fclose(H);
					status = shutdown(*ClientSocket, 2);

					if (status == SOCKET_ERROR)
					{
						printf("Shutdown of client unsuccessful\n");
						g_console.Format( "Shutdown of client unsuccessful\n");
						status = closesocket(*ClientSocket);
					}

					if (status == SOCKET_ERROR)
					{
						printf("closesocket() unsuccessful\n");
						g_console.Format( "closesocket() unsuccessful\n");
						free(ClientSocket);
					}
					return;
				}
			}
		}
		fclose(H);
		LeaveCriticalSection(&fileLock);//XBOX SECURITY FILE ACCESS
	}

	//
	// We are done, so close the socket and free the memory:
	status = shutdown(*ClientSocket, 2);

	if (status == SOCKET_ERROR)
	{
		printf("Shutdown of client unsuccessful\n");
		g_console.Format( "Shutdown of client unsuccessful\n");
		status = closesocket(*ClientSocket);
	}

	if (status == SOCKET_ERROR)
	{
		printf("closesocket() unsuccessful\n");
		g_console.Format( "closesocket() unsuccessful\n");
		free(ClientSocket);
	}
}

