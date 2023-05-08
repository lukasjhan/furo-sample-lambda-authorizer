require('dotenv').config({ silent: true });

const jwt = require('jsonwebtoken');

// Furo에서 발급받은 JWT Secret로 교체 (프로젝트 -> 개발자 도구 -> JWT Secret)
const SECRET_KEY = '79ca58c37f596afb8183e185ae571b316d2bf411d8246fe5ea3c42906f640dde';

const getPolicyDocument = (effect, resource) => {
    const policyDocument = {
        Version: '2012-10-17', // default version
        Statement: [{
            Action: 'execute-api:Invoke', // default action
            Effect: effect,
            Resource: resource,
        }]
    };
    return policyDocument;
}


// extract and return the Bearer Token from the Lambda event parameters
const getToken = (params) => {
    if (!params.type || params.type !== 'TOKEN') {
        throw new Error('Expected "event.type" parameter to have value "TOKEN"');
    }

    const tokenString = params.authorizationToken;
    if (!tokenString) {
        throw new Error('Expected "event.authorizationToken" parameter to be set');
    }

    const match = tokenString.match(/^Bearer (.*)$/);
    if (!match || match.length < 2) {
        throw new Error(`Invalid Authorization token - ${tokenString} does not match "Bearer .*"`);
    }
    return match[1];
}

module.exports.authenticate = (params) => {
    console.log(params);
    const token = getToken(params);

    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header) {
        throw new Error('invalid token');
    }

    const user = jwt.verify(token, SECRET_KEY);
    if(user) {
        return {
            policyDocument: getPolicyDocument('Allow', params.methodArn)
        }
    } else {
        throw new Error('invalid token');
    }
}