#include <windows.h>
#include <versionhelpers.h>

BOOL IsUserInAdminGroup() {
	HANDLE hProcess = NULL;
	HANDLE hProcessToken = NULL;
	BOOL fIsAdmin = FALSE;

	// get handle to our process token
	hProcess = GetCurrentProcess();
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken)) {
		//GetLastError();
		//Error place 1
		goto Exit;
	}

	// get admin SID
	char AdminSID[SECURITY_MAX_SID_SIZE];
	DWORD dwLength = sizeof(AdminSID);
	if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &AdminSID, &dwLength)) {
		//GetLastError();
		//Error place 2
		goto Exit;
	}

	// check to see if the current token contains admin SID
	if (!CheckTokenMembership(NULL, &AdminSID, &fIsAdmin)) {
		//GetLastError();
		//Error place 3
		goto Exit;
	}

	if (fIsAdmin) {
		// --------------> The user is in admin group and the process is elevated. <--------------
		goto Exit;
	}

	// if the current token does not contain admin SID, it does not mean 
	// that the current user is not admin. In Vista by default the token of 
	// users in administrator group has the the admin SID filtered. We nee
	// to use the unfiltered token to do the check. 

	// XP and below, we are done.
	if (!IsWindowsVistaOrGreater()) {
		// --------------> The user is not in admin group. <--------------
		goto Exit;
	}

	HANDLE hLinkedToken = NULL;
	// get handle to linked token (will have one if we are lua)
	if (!GetTokenInformation(hProcessToken, TokenLinkedToken, (VOID *)&hLinkedToken, sizeof(HANDLE), &dwLength)) {
		DWORD err = GetLastError();
		if (err == ERROR_NO_SUCH_LOGON_SESSION || err == ERROR_PRIVILEGE_NOT_HELD) {
			// --------------> The user is not in admin group. <--------------
		}

		//err - error code
		//Error place 5
		goto Exit;
	}
	
	if (!CheckTokenMembership(hLinkedToken, &AdminSID, &fIsAdmin)) {
		//GetLastError();
		//Error place 6
	}

	CloseHandle(hLinkedToken);
Exit:
	CloseHandle(hProcessToken);
	CloseHandle(hProcess);

	/*
	if (fIsAdmin) {
		// --------------> The user is in admin group. <--------------
	} else {
		// --------------> The user is not in admin group. <--------------
	}
	*/

	return fIsAdmin;
}
