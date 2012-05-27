#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <oauth.h>
#include <curl/curl.h>

#include "DBSettings.h"

#define TOKEN_FILE "./tokens"
#define CB_VERSION "0.01"
#define DEBUG_OUT	(1)

CURL * pCurl = NULL;

int InitCurl();
void CleanUp();
int Authenticate();
char * OAuthSign(const char * url, char ** postArgs, char * consumerKey, char * consumerSecret, char * tokenKey, char * tokenSecret);
size_t CurlWriteData(void *buffer, size_t size, size_t count, void *userData);
void GetTokenAndSecret(char * input, char * token, char * secret, char * userId);
void SaveAccessTokens();
int LoadAccessTokens();

typedef enum
{
	APP_STAGE_AUTHORIZE,
	APP_STAGE_AUTHORIZED,
	APP_STAGE_WORKING
} E_APP_STAGE;


int appStage = APP_STAGE_AUTHORIZE;
char curlErrorBuffer[CURL_ERROR_SIZE];

char oauthToken[64];
char oauthTokenSecret[64];

char accessToken[64];
char accessTokenSecret[64];

char userID[64];


int main(char ** argc, int argv)
{
	printf("CurlBox Version %s (%s)\n\n", CB_VERSION, APP_ACCESS_TYPE);

	if(!InitCurl())
	{
		return 0;
	}

	if(!LoadAccessTokens())
	{
		if(!Authenticate())
		{
			printf("\ncurl error:\n%s\n", curlErrorBuffer);	
		}
	}

	CleanUp();

	return 0;
}

int InitCurl()
{
	if(curl_global_init(CURL_GLOBAL_SSL))
	{
		printf("Curl global init failed.\n");
		return 0;
	}

	pCurl = curl_easy_init();

	if(pCurl)
	{
		printf("Curl initialised.\n");
	}
	else
	{
		printf("Failed to initialise curl.\n");
	}

	return pCurl != NULL;
}

void CleanUp()
{
	curl_easy_cleanup(pCurl);
	printf("\n\n");
}

int Authenticate()
{
	char * signedURL = NULL;
	char * postArgs = NULL;
	
	signedURL = OAuthSign(APP_AUTH_URL, &postArgs, OAUTH_KEY, OAUTH_SECRET, NULL, NULL);

	if(DEBUG_OUT)
		printf("Signed URL: %s\n\n", signedURL);
	curl_easy_setopt(pCurl, CURLOPT_URL, signedURL);
	curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, postArgs);
	curl_easy_setopt(pCurl, CURLOPT_ERRORBUFFER, curlErrorBuffer);
	curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, CurlWriteData);

	if(curl_easy_perform(pCurl))
	{
		return 0;
	}

	free(postArgs);
	free(signedURL);

	// wait for user to authorize the app via their browser...
	printf("Press enter once you have authorized access...\n");
	getchar();

	// now try and get an access token
	appStage = APP_STAGE_AUTHORIZED;

	signedURL = OAuthSign(APP_ACCESS_TOKEN_URL, &postArgs, OAUTH_KEY, OAUTH_SECRET, oauthToken, oauthTokenSecret);

	if(DEBUG_OUT)
	{
		printf("\nRequest token signed URL:\n%s\n\n", signedURL);
	}

	curl_easy_setopt(pCurl, CURLOPT_URL, signedURL);
	curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, postArgs);

	if(curl_easy_perform(pCurl))
	{
		return 0;
	}

	return 1;	
}

char * OAuthSign(const char * url, char ** postArgs, char * consumerKey, char * consumerSecret, char * tokenKey, char * tokenSecret)
{
	return oauth_sign_url2(url, postArgs, OA_HMAC, "POST", consumerKey, consumerSecret, tokenKey, tokenSecret); 
}

size_t CurlWriteData(void *buffer, size_t size, size_t count, void *userData)
{
	// buffer is not null terminated..
	char * outBuffer = malloc((size * count) + 2);
	memcpy(outBuffer, buffer, size * count);
	outBuffer[(size * count) - 1] = '&';
	outBuffer[size * count] = '\0';

	if(appStage == APP_STAGE_AUTHORIZE)
	{
		GetTokenAndSecret(outBuffer, oauthToken, oauthTokenSecret, NULL);

		if(DEBUG_OUT)
		{
			printf("%s\n%s\n%s\n\n", outBuffer, oauthTokenSecret, oauthToken);
		}

		printf("Please paste this URL into a browser and follow the instructions to authorize this application:\n%s?%s\n\n", APP_USER_AUTH_URL, outBuffer);
	}
	else if(appStage == APP_STAGE_AUTHORIZED)
	{
		GetTokenAndSecret(outBuffer, accessToken, accessTokenSecret, userID);

		if(DEBUG_OUT)
		{
			printf("%s\n%s\n%s\n\n", outBuffer, accessTokenSecret, accessToken);
		}

		SaveAccessTokens();
	}

	free(outBuffer);

	// return the size processed to signify success to libcurl
	return (size * count);
}

void GetTokenAndSecret(char * input, char * token, char * secret, char * user)
{
	char * part = strtok(input, "=");

	while(part)
	{
		if(!strcmp(part, "oauth_token"))
		{
			sprintf(token, "%s", strtok(NULL, "&"));
		}
		else if(!strcmp(part, "oauth_token_secret"))
		{
			sprintf(secret, "%s", strtok(NULL, "&"));
		}
		else if(user && !strcmp(part, "uid"))
		{
			sprintf(user, "%s", strtok(NULL, "&"));
		}

		part = strtok(NULL, "=");
	}
}

void SaveAccessTokens()
{
	FILE * pFile = fopen(TOKEN_FILE, "w+");
	
	if(pFile)
	{
		fprintf(pFile, "%s %s %s", accessToken, accessTokenSecret, userID);
		fclose(pFile);
	}
}

int LoadAccessTokens()
{
	FILE * pFile = fopen(TOKEN_FILE, "r");

	if(pFile)
	{
		fscanf(pFile, "%s %s %s", accessToken, accessTokenSecret, userID);
		fclose(pFile);

		if(DEBUG_OUT)
		{
			printf("Loaded tokens: %s - %s - %s\n\n", accessToken, accessTokenSecret, userID);
		}

		return 1;
	}

	return 0;
}
