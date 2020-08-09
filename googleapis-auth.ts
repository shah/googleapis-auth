import * as fs from "fs";
import { Credentials, OAuth2Client } from "google-auth-library";
import { google } from "googleapis";
import * as readline from "readline";

export interface GoogleApiAuthorization {
    readonly isGoogleApiAuthorized: boolean;
}

export interface GoogleApiAuthorizedClient extends GoogleApiAuthorization {
    readonly authorizedApiClient: OAuth2Client;
    readonly cachedCredentials: GoogleAuthCachedCredentials;
}

export function isGoogleApiAuthorized(o: any): o is GoogleApiAuthorizedClient {
    return o && "authorizedApiClient" in o;
}

export interface GoogleApiClientAccessParams {
    readonly installed: {
        readonly client_id: string,
        readonly project_id: string,
        readonly auth_uri: string,
        readonly token_uri: string,
        readonly auth_provider_x509_cert_url: string,
        readonly client_secret: string,
        readonly redirect_uris: string[]
    }
}

export interface GoogleAuthCachedCredentials {
    readonly scopes: GoogleAuthCredentialsScopes;
    readonly credentials: Credentials;
}

export interface GoogleAuthCredentialsCache {
    cachedCredentials(oAuth2Client: OAuth2Client): GoogleAuthCachedCredentials | undefined;
}

export type FlexibleParamsSource = string | number | Buffer | URL;

export interface GoogleApiClientAccessParamsErrorHandler {
    (clientAccessParamsSource: FlexibleParamsSource, error: Error): void;
}

export function consoleGoogleApiClientAccessParamsErrorHandler(clientAccessParamsSource: FlexibleParamsSource, error: Error): void {
    console.error(`Unable to obtain Google API Client Access Params from ${clientAccessParamsSource}: ${error}`)
}

export function authorize(
    clientAccessParamsSource: FlexibleParamsSource, credCache: GoogleAuthCredentialsCache,
    onError: GoogleApiClientAccessParamsErrorHandler = consoleGoogleApiClientAccessParamsErrorHandler): GoogleApiAuthorization | GoogleApiAuthorizedClient | undefined {
    try {
        const clientAccessParamsBuff = fs.readFileSync(clientAccessParamsSource);
        const clientAccessParams = JSON.parse(clientAccessParamsBuff.toString()) as GoogleApiClientAccessParams;
        const { client_secret, client_id, redirect_uris } = clientAccessParams.installed;
        const aplClient = new google.auth.OAuth2(
            client_id,
            client_secret,
            redirect_uris[0],
        );
        const cc = credCache.cachedCredentials(aplClient);
        if (cc) {
            aplClient.setCredentials(cc.credentials);
            return {
                isGoogleApiAuthorized: true,
                authorizedApiClient: aplClient,
                cachedCredentials: cc
            }
        }
    } catch (clientAccessSourceError) {
        onError(clientAccessParamsSource, clientAccessSourceError);
    }
    return {
        isGoogleApiAuthorized: false
    }
}

export type GoogleAuthCredentialsScopes = string[];
export type LocalParamsSource = string | number;

export class LocalFileCliCache implements GoogleAuthCredentialsCache {
    static readonly DEFAULT_SCOPES: string[] = ["https://www.googleapis.com/auth/gmail.readonly"];
    readonly scopes: GoogleAuthCredentialsScopes;

    constructor(readonly tokenParamsSource: LocalParamsSource, scopes?: GoogleAuthCredentialsScopes) {
        this.scopes = scopes || LocalFileCliCache.DEFAULT_SCOPES;
    }

    /**
     * Get and store new token after prompting for user authorization at the command line.
     * @param {google.auth.OAuth2} oAuth2Client The OAuth2 client to get token for.
     */
    cachedCredentials(oAuth2Client: OAuth2Client): GoogleAuthCachedCredentials | undefined {
        let result: GoogleAuthCachedCredentials | undefined = undefined;
        try {
            const tokenParamsBuff = fs.readFileSync(this.tokenParamsSource);
            result = {
                credentials: JSON.parse(tokenParamsBuff.toString()) as Credentials,
                scopes: this.scopes
            }
        } catch (tokenSourceError) {
            const authUrl = oAuth2Client.generateAuthUrl({
                access_type: "offline",
                scope: this.scopes,
            });
            console.log("Authorize this app by visiting this url:", authUrl);
            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout,
            });
            const self = this;
            rl.question("Enter the code from that page here: ", (code) => {
                rl.close();
                oAuth2Client.getToken(code, (err, token) => {
                    if (err || !token) return console.error("Unable to obtain oAuth tokens: " + err);
                    result = {
                        credentials: token,
                        scopes: this.scopes
                    }
                    // Store the token to disk for later program executions
                    fs.writeFileSync(this.tokenParamsSource, JSON.stringify(result));
                });
            });
        }
        return result;
    }
}
