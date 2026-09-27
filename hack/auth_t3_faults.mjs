// Loaded only inside the dedicated candidate fault environment.
import {execFileSync} from 'node:child_process';
export const docker=(args,stdin)=>execFileSync('docker',args,{input:stdin,encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:65000}).trim();
