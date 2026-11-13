const {spawn} = require('node:child_process');
const path = require('node:path');
module.exports = class StudyProvider {
  id() { return 'volpilot-integrity-study'; }
  async callApi(prompt, context) {
    return new Promise((resolve, reject) => {
      const child=spawn(process.env.RQ4_UV || 'uv',
        ['run','--no-sync','--offline','python',path.join(__dirname,'study.py')],
        {cwd:path.resolve(__dirname,'../../..'),env:{...process.env,
          UV_CACHE_DIR:path.join(__dirname,'.cache/uv'),PYTHONDONTWRITEBYTECODE:'1'}});
      let out='',err='';
      child.stdout.on('data',x=>out+=x);child.stderr.on('data',x=>err+=x);
      child.on('error',reject);
      child.on('close',code=>{
        if(code!==0)return resolve({error:`Study runner exited ${code}: ${err.slice(-1500)}`});
        try{resolve(JSON.parse(out));}catch(e){resolve({error:`Invalid runner JSON: ${e.message}`});}
      });
      child.stdin.end(JSON.stringify({case_json:context.vars.case_json,repeat:context.vars.repeat}));
    });
  }
};
