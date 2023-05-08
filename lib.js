const jwt = require("jsonwebtoken");

const SECRET_KEY = "INPUT SECRET KEY HERE";

const getPolicyDocument = (effect, resource) => {
  const policyDocument = {
    Version: "2012-10-17", // default version
    Statement: [
      {
        Action: "execute-api:Invoke", // default action
        Effect: effect,
        Resource: resource,
      },
    ],
  };
  return policyDocument;
};

// extract and return the Bearer Token from the Lambda event parameters
const getToken = (params) => {
  if (!params.type || params.type !== "TOKEN") {
    throw new Error('Expected "event.type" parameter to have value "TOKEN"');
  }

  const tokenString = params.authorizationToken;
  if (!tokenString) {
    throw new Error('Expected "event.authorizationToken" parameter to be set');
  }

  const match = tokenString.match(/^Bearer (.*)$/);
  if (!match || match.length < 2) {
    throw new Error(
      `Invalid Authorization token - ${tokenString} does not match "Bearer .*"`
    );
  }
  return match[1];
};

module.exports.authenticate = (params) => {
  console.log(params);
  const token = getToken(params);

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header) {
    throw new Error("invalid token");
  }

  const user = jwt.verify(token, SECRET_KEY);
  if (user) {
    return {
      policyDocument: getPolicyDocument("Allow", params.methodArn),
    };
  } else {
    throw new Error("invalid token");
  }
};
