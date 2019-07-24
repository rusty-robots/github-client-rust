const frisby = require('frisby');

it('should response to the setup url', function () {
  return frisby
    .get('http://localhost:9999/github/setup')
    .expect('status', 200);
});
