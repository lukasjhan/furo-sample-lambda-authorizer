const lib = require("./lib");
let data;

module.exports.handler = async (event, context, callback) => {
  try {
    data = await lib.authenticate(event);
  } catch (err) {
    console.log(err);
    return context.fail("Unauthorized");
  }
  return data;
};
