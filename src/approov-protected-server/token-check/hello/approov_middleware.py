from django.http import JsonResponse
from os import getenv
from dotenv import load_dotenv, find_dotenv
import base64
import jwt # https://github.com/jpadilla/pyjwt/

# @link https://django.readthedocs.io/en/stable/topics/http/middleware.html
class ApproovMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

        load_dotenv(find_dotenv(), override=True)

        # Token secret value obtained with the Approov CLI tool:
        #  - approov secret -get
        approov_base64_secret = getenv('APPROOV_BASE64_SECRET')

        if approov_base64_secret == None:
            raise ValueError("Missing the value for environment variable: APPROOV_BASE64_SECRET")

        self.APPROOV_SECRET = base64.b64decode(approov_base64_secret)

    def __call__(self, request):
        approov_token_claims = self.verifyApproovToken(request)

        if approov_token_claims == None:
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
