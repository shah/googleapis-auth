import * as gaa from "./googleapis-auth";

const apiAuth = gaa.authorize(".secrets/api-access.json", new gaa.LocalFileCliCache(".secrets/stored-oauth-tokens.json"));
if (gaa.isGoogleApiAuthorized(apiAuth)) {
    console.log("Access to Google APIs authorized for scopes", apiAuth.cachedCredentials.scopes);
} else {
    console.error("Google APIs access failed.");
}
