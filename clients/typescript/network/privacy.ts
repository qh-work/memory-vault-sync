/** The existing finite publication heuristic, used only by guarded Hint exports.
 * This is not comprehensive DLP. It does not alter local memory or grant access.
 * Pattern sources mirror memory_vault_privacy.py; errors never echo matches.
 */
import { NetworkCryptoError } from './crypto.ts';

const MAX_SCAN_BYTES = 128 * 1024 * 1024, MAX_SCAN_RECORDS = 100000;
function fail(code:string):never { throw new NetworkCryptoError(code); }
// Python's Unicode word/space classes differ from JavaScript's ASCII \\b and
// \\w. Spell out those classes when compiling the shared finite patterns.
const WORD = String.raw`[\p{L}\p{N}_]`;
const BOUNDARY = `(?:(?<!${WORD})(?=${WORD})|(?<=${WORD})(?!${WORD}))`;
const SPACE = String.raw`[\p{White_Space}\u001c-\u001f]`;
function pattern(source:string,insensitive:boolean):RegExp {
  source=source.replace('(?i)','');
  if(insensitive){
    // Python IGNORECASE also folds dotted/dotless I into ASCII i. JS /iu
    // already handles long s and Kelvin sign, but omits these two forms.
    let folded='',position=0;
    while(position<source.length){
      const character=source[position++];
      if(character==='\\'){folded+=character+(source[position++]??'');continue;}
      if(character==='['){
        let field='';
        while(position<source.length){const next=source[position++];if(next==='\\'){field+=next+(source[position++]??'');continue;}if(next===']')break;field+=next;}
        folded+='['+field+(/[iI]|A-Z|a-z/.test(field)?String.raw`\u0130\u0131`:'')+']';continue;
      }
      folded+=character==='i'||character==='I'?String.raw`[iI\u0130\u0131]`:character;
    }
    source=folded;
  }
  let adapted='',inClass=false;
  for(let position=0;position<source.length;position++){
    const character=source[position];
    if(character==='\\'){
      const token=source[++position];
      adapted+=token==='b'?BOUNDARY:token==='d'?String.raw`\p{Nd}`:
        token==='s'?(inClass?String.raw`\p{White_Space}\u001c-\u001f`:SPACE):
        token==='S'?String.raw`[^\p{White_Space}\u001c-\u001f]`:
        token==='"'||token==="'"?token:'\\'+token;
    }else{if(character==='[')inClass=true;if(character===']')inClass=false;adapted+=character;}
  }
  return new RegExp(adapted,insensitive?'iu':'u');
}
const SECRETS = [
  pattern("-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",false),
  pattern("(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",false),
  pattern("(?<![A-Za-z0-9_])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",false),
  pattern("\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b",false),
  pattern("AIza[A-Za-z0-9_-]{20,}",false),
  pattern("\\b(?:ya29\\.|GOCSPX-)[A-Za-z0-9_-]{20,}\\b",false),
  pattern("(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])",false),
  pattern("(?i)\\bauthorization\\s*:\\s*(?:bearer|basic)\\s+[A-Za-z0-9._~+/=-]{12,}",true),
  pattern("(?i)\\bBearer\\s+[A-Za-z0-9._~+/=-]{20,}",true),
  pattern("\\bx(?:ox[baprs]|app)-[A-Za-z0-9-]{10,}\\b",false),
  pattern("\\b(?:glpat|glrt|gloas)-[A-Za-z0-9_-]{20,}\\b",false),
  pattern("\\b(?:npm_|hf_)[A-Za-z0-9]{30,}\\b",false),
  pattern("\\b(?:pypi-|sq0(?:atp|csp)-)[A-Za-z0-9_-]{20,}\\b",false),
  pattern("\\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\\b",false),
  pattern("\\bSG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}\\b",false),
  pattern("\\b\\d{8,12}:[A-Za-z0-9_-]{30,}\\b",false),
  pattern("\\bdop_v1_[0-9a-fA-F]{64}\\b",false),
  pattern("(?i)\\b(?:Cookie|Set-Cookie)\\s*:\\s*\\S+",true),
  pattern("(?i)(?:--session-token|session[_-]?token)(?:\\s*[:=]\\s*|\\s+)[\\\"']?[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])",true),
  pattern("(?i)(?:\\[\\[\\s*)?memory-vault-handoff\\s*:\\s*[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])",true),
  pattern("mvrd_[A-Za-z0-9_-]{43}",false),
  pattern("(?i)\\b(?:password|passwd|api[_-]?(?:key|token)|access[_-]?token|refresh[_-]?token|oauth[_-]?token|session[_-]?token|client[_-]?secret|secret[_-]?key|private[_-]?key|webhook[_-]?secret)\\s*[:=]\\s*[\\\"']?[^\\s\\\"']{12,}",true),
  pattern("\\bhttps?://[^\\s/@:]{1,128}:[^\\s/@]{1,256}@",false),
];
const LOCAL_PATHS = [
  pattern("(?<![A-Za-z0-9])/(?:Users|home|private|var|tmp|Volumes)/[^\\s\\\"<>]+",false),
  pattern("(?i)\\b[A-Z]:[\\\\/](?:Users|Documents and Settings)[\\\\/][^\\r\\n\\\"<>]+",true),
  pattern("(?:^|[\\s\\\"'(`])/(?:Users|home|root|tmp|var|private|Volumes|content|mnt|etc|opt|Applications|Library|System|bin|sbin|run|dev|proc|sys|srv|data|workspace|workspaces|project|projects|repo|repos|build|app|usr/(?:local|bin|sbin|share|lib|include))/",false),
  pattern("(?:^|[\\s\\\"'(`])[A-Za-z]:[\\\\/]",false),
  pattern("(?:^|[\\s\\\"'(`])\\\\\\\\[^\\\\\\s]+\\\\[^\\\\\\s]+",false),
  pattern("(?:^|[\\s\\\"'(`])~[\\\\/]",false),
];

/** Match the Python scanner's raw + NFC string traversal and finite budgets.
 * Inputs here are validated immutable records, not executable object content.
 */
export function assertPublishable(records:readonly Record<string,unknown>[]):void {
  let remaining=MAX_SCAN_BYTES,nodes=MAX_SCAN_BYTES,count=0;
  for(const record of records){
    if(++count>MAX_SCAN_RECORDS||record===null||typeof record!=='object'||Array.isArray(record))fail('publication_scan_limit');
    let secret=false,local=false;
    const pending:{iterator:Iterator<unknown>;depth:number}[]=[{iterator:[record][Symbol.iterator](),depth:0}];
    while(pending.length){
      const frame=pending[pending.length-1],next=frame.iterator.next();
      if(next.done){pending.pop();continue;}
      if(frame.depth>32||--nodes<0)fail('publication_scan_limit');
      const value=next.value;
      if(Array.isArray(value)){pending.push({iterator:value[Symbol.iterator](),depth:frame.depth+1});}
      else if(value!==null&&typeof value==='object'){
        function* parts():IterableIterator<unknown>{for(const [key,child] of Object.entries(value)){yield key;yield child;}}
        pending.push({iterator:parts(),depth:frame.depth+1});
      }else if(typeof value==='string'){
        const raw=Buffer.from(value,'utf8');if(raw.toString('utf8')!==value)fail('publication_invalid_text');
        remaining-=raw.length;if(remaining<0)fail('publication_scan_limit');
        const normalized=value.normalize('NFC'),projections=normalized===value?[value]:[value,normalized];
        for(const text of projections){
          secret ||= SECRETS.some(expression=>expression.test(text));
          local ||= LOCAL_PATHS.some(expression=>expression.test(text));
        }
      }
    }
    if(secret)fail('publication_secret_detected');
    if(local)fail('publication_local_path_detected');
  }
}
