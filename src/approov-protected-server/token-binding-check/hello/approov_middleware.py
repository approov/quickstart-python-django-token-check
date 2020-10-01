from django.http import JsonResponse
from os import getenv
from dotenv import load_dotenv, find_dotenv
import base64
import jwt # https://github.com/jpadilla/pyjwt/
import hashlib

# @link https://django.readthedocs.io/en/stable/topics/http/middleware.html
class ApproovMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

        load_dotenv(find_dotenv(), override=True)

        # Token secret value obtained with the Approov CLI tool:
        #  - approov secret <admin.tok> -get
        approov_base64_secret = getenv('APPROOV_BASE64_SECRET')

        if approov_base64_secret == None:
            raise ValueError("Missing the value for environment variable: APPROOV_BASE64_SECRET")

        self.APPROOV_SECRET = base64.b64decode(approov_base64_secret)

    def __call__(self, request):
        approov_token_claims = self.verifyApproovToken(request)

        if approov_token_claims == None:
            return JsonResponse({}, status = 401)

        if self.verifyApproovTokenBinding(request, approov_token_claims) == False:
            return JsonResponse({}, status = 401)

        return self.get_response(request)

    # @link https://approov.io/docs/latest/approov-usage-documentation/#backend-integration
    def verifyApproovToken(self, request):
        approov_token = request.headers.get("Approov-Token")

        # If we didn't find a token, then reject the request.
        if approov_token == None:
            # You may want to add some logging here.
            return None

        try:
            # Decode the Approov token explicitly with the HS256 algorithm to avoid
            # the algorithm None attack.
            approov_token_claims = jwt.decode(approov_token, self.APPROOV_SECRET, algorithms=['HS256'])
            return approov_token_claims
        except jwt.ExpiredSignatureError as e:
            # You may want to add some logging here.
            return None
        except jwt.InvalidTokenError as e:
            # You may want to add some logging here.
            return None

    # @link https://approov.io/docs/latest/approov-usage-documentation/#token-binding
    def verifyApproovTokenBinding(self, request, approov_token_claims):
        # Note that the `pay` claim will, under normal circumstances, be present,
        # but if the Approov failover system is enabled, then no claim will be
        # present, and in this case you want to return true, otherwise you will not
        # be able to benefit from the redundancy afforded by the failover system.
        if not 'pay' in approov_token_claims:
            # You may want to add some logging here.
            return True

        # We use the Authorization token, but feel free to use another header in
        # the request. Beqar in mind that it needs to be the same header used in the
        # mobile app to qbind the request with the Approov token.
        token_binding_header = request.headers.get("Authorization")

        if not token_binding_header:
            # You may want to add some logging here.
            return False

        # We need to hash and base64 encode the token binding header, because that's
        # how it was included in the Approov token on the mobile app.
        token_binding_header_hash = hashlib.sha256(token_binding_header.encode('utf-8')).digest()
        token_binding_header_encoded = base64.b64encode(token_binding_header_hash).decode('utf-8')

        if approov_token_claims['pay'] == token_binding_header_encoded:
            return True

        return False
