"""Module containing functions and class for working with the AWS Lambda Service"""

import re
import json
import base64
import typing
import logging


from requests_toolbelt.multipart import decoder


logger = logging.getLogger("wisecode-aws-sdk:lambda")


def extract_body_from_sqs_event(sqs_event: typing.Dict) -> typing.Generator[typing.Dict, None, None]:
    """Parses the SQS message from a SQS lambda event and returns a generator for all records in the 
    SQS message

    :param sqs_event: SQS intergration event sent to Lambda service when a Message is delivered.
    :type sqs_event: typing.Dict
    :yield: A generator that yields each record in the SQS message body parsed to a dictionary
    :rtype: typing.Generator[typing.Dict, None, None]:
    """
    for record in sqs_event["Records"]:
        body = json.loads(record["body"])

        yield body


def extract_body_from_apigatewayv2_event(apigatewayv2_event: typing.Dict) -> typing.Dict:
    """Parses the API Gateway v2 event into a Python Dictionary object

    :param apigatewayv2_event: API Gateway v2 integration Lambda event
    :type apigatewayv2_event: typing.Dict
    :return: The body key of the API Gateway v2 event parse as a JSON to a dictionary
    :rtype: typing.Dict
    """
    return json.loads(apigatewayv2_event["body"])


class HTTPResponse:
    """Simple python data class that abstracts represents an API Gateway v2 HTTP lambda response.
    The api_gateway_response method converts this class into the correct structure as expected by
    the API Gateway HTTP lambda integration.
    """
    def __init__(self, cookies: typing.List[str] = None, is_base64_encoded: bool = False, status_code: int = 200, headers: typing.Dict[str, str] = None, body: str = "") -> None:
        """Constructs an instance of the HTTPResponse class

        :param cookies: List of cookies to add to API Gateway response, defaults to None
        :type cookies: typing.List[str], optional
        :param is_base64_encoded: Indicates whether results are base64 encoded or not, defaults to False
        :type is_base64_encoded: bool, optional
        :param status_code: HTTP response code for result of lambda execution, defaults to 200
        :type status_code: int, optional
        :param headers: Dictionary of headers and their values to add to API Gateway response, defaults to None
        :type headers: typing.Dict[str, str], optional
        :param body: Reponse body, as a string, for API Gateway response, defaults to ""
        :type body: str, optional
        """
        self.cookies = cookies if cookies is not None else []
        self.is_base64_encoded = is_base64_encoded
        self.status_code = status_code
        self.headers = headers if headers is not None else {}
        self.body = body

    def error(self, ex: Exception, traceback: str, status_code: int = 500) -> None:
        """Generate an error response for API Gateway to send back.

        :param ex: Exception class that was raise by error
        :type ex: Exception
        :param traceback: Error message to return to caller
        :type traceback: str
        :param status_code: HTTP response code to return to caller, defaults to 500
        :type status_code: int, optional
        """
        logger.exception(ex)
        self.status_code = status_code
        self.add_body({
            "errorMessage": traceback
        })

    def add_body(self, body: typing.Dict[str, object]) -> None:
        """Convenience method that takes a dictionary and json stringifys it to 
        add as the body of the repsonse

        :param body: Python dictionary of response body to return to caller
        :type body: typing.Dict
        """
        self.body = json.dumps(body, sort_keys=True, default=str)

    def add_headers(self, headers: typing.Dict[str, str]) -> None:
        """Add HTTP headers to this response object

        :param headers: Dictionary of key value pairs representing the headers to add to request
        :type headers: typing.Dict[str, str]
        """
        self.headers.update(headers)

    def api_gateway_response(self) -> typing.Dict[str, object]:
        """Structure instance into the format required by API Gateway v2 HTTP lambda
        integration

        :return: A dictionary following API Gateway v2s response requirements
        :rtype: typing.Dict[str, object
        """
        return {
            "cookies" : self.cookies,
            "isBase64Encoded": self.is_base64_encoded,
            "statusCode": self.status_code,
            "headers": self.headers,
            "body": self.body
        }

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HTTPResponse):
            return False

        return self.cookies == other.cookies \
            and self.is_base64_encoded == other.is_base64_encoded \
            and self.status_code == other.status_code \
            and self.headers == other.headers \
            and self.body == other.body

    def __repr__(self) -> str:
        return json.dumps(self.api_gateway_response())


class HTTPRequest:
    """Simple python data class that represents an API Gateway v2 lambda integration event.
    """
    def __init__(self, method: str, route: str, headers: typing.Dict = None, path_parameters: typing.Dict[str, str] = None,
        query_string_parameters: typing.Dict[str, str] = None, body: str = "") -> None:
        self.method = method
        self.route = route
        self.path_parameters = path_parameters if path_parameters is not None else {}
        self.query_string_parameters = query_string_parameters if query_string_parameters is not None else {}
        self.headers = headers
        self.body = body
        self.route_sections = route.split("/")
        self.bearer_token = self.parse_bearer_token()

    @classmethod
    def parse_api_gateway_v2_event(cls, event: typing.Dict[str, object]) -> HTTPRequest:
        """Parses an API Gateway v2 lambda integration event and returns a HTTPRequest object instance

        :param event: A dictionary representing an API Gateway v2 lambda integration event
        :type event: typing.Dict[str, object]
        :return: The HTTPRequest object instance constructed from the provided API Gateway v2 event
        :rtype: HTTPRequest
        """
        logger.debug(f"HTTPRequest parsing event: {event}")
        req_context = event["requestContext"]
        req_http= req_context["http"]
        request = HTTPRequest(
            method=req_http["method"],
            route=req_http["path"],
            path_parameters=event.get("pathParameters"),
            query_string_parameters=event.get("queryStringParameters"),
            body=event.get("body", ""),
            headers=event.get("headers", {})
        )
        logger.debug(f"Parsed event to HTTPRequest: {request}")
        return request

    def parse_bearer_token(self):
        """Parses the Authorization header Bearer token

        :return: JWT Bearer token
        :rtype: typing.Optional[str]
        """

        token = None
        if self.headers:
            authorization_header = self.headers.get("authorization")
            if authorization_header:
                token = authorization_header.split(" ")[1]

        return token

    def parse_json_body(self) -> typing.Dict[str, object]:
        """Parses the request's body attribute as a stringified json and returns the 
        resulting dictionary 

        :return: Dictionary of the stringified json body
        :rtype: typing.Dict[str, object]
        """
        return json.loads(self.body)

    def parse_multipart_body(self):
        """
        Parses the request's body attribute as multipart form data and returns the resulting dictionary

        :return: Dictionary of parsed multipart form data
        :rtype: typing.Dict[str, object]
        """

        def parse_content_disposition_header(content_disposition: bytes):
            """
            Parses the content disposition header tokens
            """
            tokens = content_disposition.decode().split(";")
            return {
                k.strip().replace('"', ""): v.strip().replace('"', "")
                for [k, v] in [token.split("=") for token in tokens if "=" in token]
            }

        logger.debug("Parsing multipart body")
        logger.debug(f"Body type {type(self.body)}")
        parsed_multipart_data = {}
        body_for_decoder = base64.b64decode(self.body)
        for part in decoder.MultipartDecoder(body_for_decoder, self.headers.get("content-type")).parts:
            logger.debug(f"Parsing part {part}")
            content_disposition = part.headers.get(b"Content-Disposition")
            logger.debug(f"Part content-disposition {content_disposition}")
            header_dict = parse_content_disposition_header(content_disposition)
            logger.debug(f"Part header dict {header_dict}")
            part_name = header_dict.get("name")
            logger.debug(f"Part name {part_name}")
            if part_name == "json":
                part_value = json.loads(part.text)
            elif part_name == "file":
                part_value = part.content
            else:
                part_value = part.text

            logger.debug(f"Part value {part_value}")
            parsed_multipart_data[part_name] = part_value

        return parsed_multipart_data

    def match_route(self, route: str) -> bool:
        """Checks if the given route string matches any part of the request's route attribute. 

        :param route: Route string to match against the request's route attribute
        :type route: str
        :return: True if the provided route string does match against the request's route attribute and False otherwise
        :rtype: bool
        """
        logger.debug(f"Checking if {route} matches request's {self.route}...")
        pattern = re.compile(route)
        result = pattern.search(self.route) is not None
        logger.debug(f"Result={result}")

        return result

    def match_action(self, route: str, method: str) -> bool:
        """Checks if the given route string matches any part of the request's route attribute, and the HTTP method
        matches.

        :param route: Route string to match against the request's route attribute
        :type route: str
        :param method: HTTP method string to match against the request's method
        :type route: str
        :return: True if the provided route string and method string do match against the request and False otherwise
        :rtype: bool
        """

        result = self.match_route(route)
        if result and method != self.method:
            result = False

        return result

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HTTPRequest):
            return False

        return self.method == other.method \
            and self.route == other.route \
            and self.path_parameters == other.path_parameters \
            and self.query_string_parameters == other.query_string_parameters \
            and self.body == other.body

    def __repr__(self) -> str:
        request_metadata = {
            "method": self.method,
            "route": self.route,
            "path_parameters": self.path_parameters,
            "query_string_parameters": self.query_string_parameters,
        }
        if isinstance(self.body, str):
            request_metadata["body"] = self.body

        return json.dumps(request_metadata)