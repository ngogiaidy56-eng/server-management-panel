'use strict';
const crypto=require('node:crypto'),os=require('node:os'),path=require('node:path');
const express=require('express'),helmet=require('helmet'),{rateLimit}=require('express-rate-limit'),{Pool}=require('pg');
const VERSION=require('./package.json').version,COOKIE='hsp_session',ROLES=new Set(['admin','operator','viewer']),scrypt=require('node:util').promisify(crypto.scrypt);
const token=()=>crypto.randomBytes(32).toString('base64url');
const tokenHash=(value,secret)=>crypto.createHmac('sha256',String(secret)).update(String(value)).digest('hex');
function cookies(header){const out=Object.create(null);String(header||'').split(';').forEach(p=>{const i=p.indexOf('=');if(i<1)return;try{out[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1).trim())}catch(_){}});return out;}
function setCookie(v,age,secure){return COOKIE+'='+encodeURIComponent(v)+'; Path=/; HttpOnly; SameSite=Strict; Max-Age='+age+(secure?'; Secure':'');}
async function makePasswordHash(password){if(typeof password!=='string'||password.length<14||password.length>256)throw Error('Password must be 14 to 256 characters.');const salt=crypto.randomBytes(16),key=await scrypt(password,salt,64,{N:16384,r:8,p:1,maxmem:67108864});return 'scrypt$'+salt.toString('base64url')+'$'+Buffer.from(key).toString('base64url');}
async function passwordMatches(password,encoded){if(typeof password!=='string'||typeof encoded!=='string')return false;const p=encoded.split('$');if(p.length!==3||p[0]!=='scrypt')return false;try{const salt=Buffer.from(p[1],'base64url'),expected=Buffer.from(p[2],'base64url');if(salt.length<16||expected.length!==64)return false;const actual=Buffer.from(await scrypt(password,salt,64,{N:16384,r:8,p:1,maxmem:67108864}));return crypto.timingSafeEqual(actual,expected)}catch(_){return false}}
function sendError(res,status,code,message){return res.status(status).json({error:{code,message}});}
function publicUser(u){return{id:u.id,email:u.email,role:u.role,active:u.active,createdAt:u.created_at};}
function allowlist(env){return new Set(String(env.RENDER_ALLOWED_SERVICE_IDS||'').split(',').map(x=>x.trim()).filter(Boolean));}
function trustedOrigin(req,env){const value=req.get('origin');if(!value)return req.get('sec-fetch-site')==='same-origin';let origin;try{origin=new URL(value).origin}catch(_){return false}if(env.APP_ORIGIN)return origin===env.APP_ORIGIN;const proto=(req.get('x-forwarded-proto')||req.protocol).split(',')[0].trim();return origin===proto+'://'+req.get('host');}
function apiRoute(fn){return(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);}
function audit(pool,req,action,type,id,detail){return pool.query('INSERT INTO audit_logs(actor_id,action,target_type,target_id,detail,ip_address) VALUES($1,$2,$3,$4,$5::jsonb,$6)',[req.user?req.user.id:null,action,type||null,id?String(id):null,JSON.stringify(detail||{}),req.ip||null]).catch(e=>console.error(JSON.stringify({event:'audit_failed',message:e.message,requestId:req.id})));}
async function renderApi(env,url,opts){if(!env.RENDER_API_KEY){const e=Error('Render API integration is not configured.');e.status=503;e.code='RENDER_NOT_CONFIGURED';throw e}const o=opts||{},r=await fetch('https://api.render.com/v1'+url,{method:o.method||'GET',headers:{Accept:'application/json',Authorization:'Bearer '+env.RENDER_API_KEY,...(o.body?{'Content-Type':'application/json'}:{})},body:o.body?JSON.stringify(o.body):undefined,signal:AbortSignal.timeout(12000)});if(!r.ok){const e=Error(r.status===429?'Render API rate limit reached.':'Render API request failed or was not authorized.');e.status=r.status===404?404:r.status===409?409:r.status===429?503:502;e.code='RENDER_API_ERROR';throw e}return r.status===204?null:r.json()}
function normalizeService(item){const s=item&&item.service?item.service:item;return{id:s.id,name:s.name||s.id,type:s.type||s.serviceType||'service',status:s.suspended==='suspended'?'suspended':s.status||s.state||'unknown',region:s.region||null,url:s.serviceDetails&&s.serviceDetails.url||s.url||null,updatedAt:s.updatedAt||null};}
function wouldLockOutSelf(actorId,targetId,patch){const b=patch||{};return String(actorId)===String(targetId)&&((Object.hasOwn(b,'active')&&b.active===false)||(Object.hasOwn(b,'role')&&b.role!=='admin'));}
function createApp(pool,env){
 const app=express();app.disable('x-powered-by');app.set('trust proxy',env.TRUST_PROXY==='false'?false:1);
 app.use((req,res,next)=>{const started=process.hrtime.bigint();req.id=crypto.randomUUID();res.setHeader('X-Request-Id',req.id);res.on('finish',()=>{const durationMs=Number(process.hrtime.bigint()-started)/1e6;console.info(JSON.stringify({event:'http_request',requestId:req.id,method:req.method,path:req.path,status:res.statusCode,durationMs:Math.round(durationMs*100)/100}));});next()});
 app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'"],imgSrc:["'self'",'data:'],connectSrc:["'self'"],objectSrc:["'none'"],baseUri:["'self'"],frameAncestors:["'none'"],formAction:["'self'"]}},referrerPolicy:{policy:'no-referrer'},crossOriginEmbedderPolicy:false}));
 app.use(express.json({limit:'32kb',strict:true}));
 app.use('/api/',(req,res,next)=>{res.setHeader('Cache-Control','no-store');res.setHeader('Pragma','no-cache');if(['POST','PUT','PATCH','DELETE'].includes(req.method)){const contentType=req.get('content-type')||'';if(!/^application\/json(?:\s*;|$)/i.test(contentType))return sendError(res,415,'JSON_REQUIRED','Mutation endpoints require Content-Type: application/json.');if(req.body===undefined)req.body={};}next()});
 app.use((req,res,next)=>{if(['POST','PUT','PATCH','DELETE'].includes(req.method)&&!trustedOrigin(req,env))return sendError(res,403,'UNTRUSTED_ORIGIN','Request origin is not allowed.');next()});
 app.use('/api/',rateLimit({windowMs:60000,limit:120,standardHeaders:true,legacyHeaders:false}));
 const loginLimit=rateLimit({windowMs:900000,limit:10,standardHeaders:true,legacyHeaders:false,message:{error:{code:'LOGIN_RATE_LIMIT',message:'Too many login attempts. Try again later.'}}});
 const auth=apiRoute(async(req,res,next)=>{const t=cookies(req.headers.cookie)[COOKIE];if(!t)return sendError(res,401,'AUTH_REQUIRED','Please sign in.');const result=await pool.query('SELECT s.csrf_token,u.id,u.email,u.role,u.active,u.created_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW() AND u.active=TRUE LIMIT 1',[tokenHash(t,env.SESSION_SECRET)]);if(!result.rows.length){res.setHeader('Set-Cookie',setCookie('',0,env.NODE_ENV==='production'));return sendError(res,401,'SESSION_EXPIRED','Session expired. Sign in again.')}req.user=result.rows[0];req.csrf=req.user.csrf_token;next()});
 const role=(...roles)=>(req,res,next)=>req.user&&roles.includes(req.user.role)?next():sendError(res,403,'FORBIDDEN','You do not have permission.');
 const csrf=(req,res,next)=>{const got=req.get('x-csrf-token')||'';if(!got||got.length!==req.csrf.length||!crypto.timingSafeEqual(Buffer.from(got),Buffer.from(req.csrf)))return sendError(res,403,'CSRF_INVALID','Security token is missing or invalid.');next()};
 const serviceAllowed=id=>{if(!/^[A-Za-z0-9_-]{3,128}$/.test(id)||!allowlist(env).has(id)){const e=Error('Service is not in the configured allowlist.');e.status=404;e.code='SERVICE_NOT_ALLOWED';throw e}};
 app.get('/healthz',apiRoute(async(_q,res)=>{try{await pool.query('SELECT 1');res.json({ok:true,service:'server-management-panel',version:VERSION})}catch(_){sendError(res,503,'DEPENDENCY_UNAVAILABLE','Required dependency unavailable.')}}));
 app.get('/api/v1/meta',(_q,res)=>res.json({service:'Server Management Panel',version:VERSION,docs:'/api/v1/meta',health:'/healthz',roles:['admin','operator','viewer']}));
 app.post('/api/v1/auth/login',loginLimit,apiRoute(async(req,res)=>{const email=typeof req.body.email==='string'?req.body.email.trim().toLowerCase():'',password=typeof req.body.password==='string'?req.body.password:'';if(!email||!password||email.length>254||password.length>256)return sendError(res,400,'INVALID_INPUT','Enter a valid email and password.');const result=await pool.query('SELECT id,email,password_hash,role,active,created_at FROM users WHERE email=$1 LIMIT 1',[email]),u=result.rows[0],matches=await passwordMatches(password,u?u.password_hash:'');if(!u||!u.active||!matches){await pool.query('INSERT INTO audit_logs(actor_id,action,target_type,target_id,detail,ip_address) VALUES(NULL,$1,$2,$3,$4::jsonb,$5)',['auth.login_failed','user',email,JSON.stringify({reason:'invalid_credentials'}),req.ip||null]).catch(()=>{});return sendError(res,401,'INVALID_CREDENTIALS','Email or password is incorrect.')}const t=token(),csrfToken=token();await pool.query("INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL '12 hours')",[tokenHash(t,env.SESSION_SECRET),u.id,csrfToken]);req.user=u;await audit(pool,req,'auth.login','user',u.id,{});res.setHeader('Set-Cookie',setCookie(t,43200,env.NODE_ENV==='production'));res.json({user:publicUser(u),csrfToken,expiresIn:43200})}));
 app.get('/api/v1/auth/me',auth,(req,res)=>res.json({user:publicUser(req.user),csrfToken:req.csrf}));
 app.post('/api/v1/auth/logout',auth,csrf,apiRoute(async(req,res)=>{await pool.query('DELETE FROM sessions WHERE token_hash=$1',[tokenHash(cookies(req.headers.cookie)[COOKIE],env.SESSION_SECRET)]);await audit(pool,req,'auth.logout','user',req.user.id,{});res.setHeader('Set-Cookie',setCookie('',0,env.NODE_ENV==='production'));res.status(204).end()}));
 app.post('/api/v1/auth/change-password',auth,csrf,apiRoute(async(req,res)=>{
  const currentPassword=typeof req.body.currentPassword==='string'?req.body.currentPassword:'';
  const newPassword=typeof req.body.newPassword==='string'?req.body.newPassword:'';
  if(!currentPassword||!newPassword||currentPassword.length>256||newPassword.length>256)return sendError(res,400,'INVALID_INPUT','Enter your current password and a valid new password.');
  const client=await pool.connect(),nextSession=token(),nextCsrf=token();
  try{
   await client.query('BEGIN');
   const result=await client.query('SELECT password_hash FROM users WHERE id=$1 AND active=TRUE FOR UPDATE',[req.user.id]);
   if(!result.rows.length){await client.query('ROLLBACK');return sendError(res,401,'ACCOUNT_UNAVAILABLE','Your account is no longer active.')}
   if(!await passwordMatches(currentPassword,result.rows[0].password_hash)){await client.query('ROLLBACK');return sendError(res,403,'CURRENT_PASSWORD_INCORRECT','The current password is incorrect.')}
   let nextHash;
   try{nextHash=await makePasswordHash(newPassword)}catch(e){await client.query('ROLLBACK');return sendError(res,400,'INVALID_PASSWORD',e.message)}
   await client.query('UPDATE users SET password_hash=$2,updated_at=NOW() WHERE id=$1',[req.user.id,nextHash]);
   await client.query('DELETE FROM sessions WHERE user_id=$1',[req.user.id]);
   await client.query("INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL '12 hours')",[tokenHash(nextSession,env.SESSION_SECRET),req.user.id,nextCsrf]);
   await client.query('COMMIT');
  }catch(e){await client.query('ROLLBACK').catch(()=>{});throw e}
  finally{client.release()}
  await audit(pool,req,'auth.password_change','user',req.user.id,{});
  res.setHeader('Set-Cookie',setCookie(nextSession,43200,env.NODE_ENV==='production'));
  res.json({ok:true,csrfToken:nextCsrf,expiresIn:43200});
 }));
 app.get('/api/v1/monitoring/local',auth,(_req,res)=>{const m=process.memoryUsage();res.json({capturedAt:new Date().toISOString(),runtime:{node:process.version,platform:process.platform,uptimeSeconds:Math.floor(process.uptime()),pid:process.pid},processMemory:{rssBytes:m.rss,heapUsedBytes:m.heapUsed,heapTotalBytes:m.heapTotal},system:{visibleCpuCount:os.availableParallelism?os.availableParallelism():os.cpus().length,loadAverage:os.loadavg(),freeMemoryBytes:os.freemem(),totalMemoryBytes:os.totalmem()},scope:'Current app instance only; not an account-wide host or Docker inventory.'})});
 app.get('/api/v1/services',auth,role('admin','operator'),apiRoute(async(_req,res)=>{const ids=allowlist(env);if(!ids.size)return res.json({services:[],integrationConfigured:!!env.RENDER_API_KEY,allowedServiceIdsConfigured:false});const data=await renderApi(env,'/services?limit=100'),items=Array.isArray(data)?data:(data.services||[]);res.json({services:items.map(normalizeService).filter(s=>ids.has(s.id)),integrationConfigured:true,allowedServiceIdsConfigured:true})}));
 app.get('/api/v1/services/:id/deploys',auth,role('admin','operator'),apiRoute(async(req,res)=>{serviceAllowed(req.params.id);const data=await renderApi(env,'/services/'+encodeURIComponent(req.params.id)+'/deploys?limit=10'),items=Array.isArray(data)?data:(data.deploys||[]);res.json({deploys:items.map(i=>{const d=i.deploy||i;return{id:d.id,status:d.status,trigger:d.trigger,commit:d.commit?{id:d.commit.id,message:d.commit.message}:null,createdAt:d.createdAt,updatedAt:d.updatedAt,finishedAt:d.finishedAt}})})}));
 app.post('/api/v1/services/:id/deploy',auth,csrf,role('admin'),apiRoute(async(req,res)=>{serviceAllowed(req.params.id);const d=await renderApi(env,'/services/'+encodeURIComponent(req.params.id)+'/deploys',{method:'POST',body:{clearCache:req.body.clearCache===true?'clear':'do_not_clear',deployMode:'build_and_deploy'}});await audit(pool,req,'render.deploy','service',req.params.id,{clearCache:req.body.clearCache===true});res.status(202).json({deploy:d})}));
 app.post('/api/v1/services/:id/restart',auth,csrf,role('admin'),apiRoute(async(req,res)=>{serviceAllowed(req.params.id);await renderApi(env,'/services/'+encodeURIComponent(req.params.id)+'/restart',{method:'POST'});await audit(pool,req,'render.restart','service',req.params.id,{});res.json({restarted:true})}));
 app.get('/api/v1/users',auth,role('admin'),apiRoute(async(_req,res)=>{const r=await pool.query('SELECT id,email,role,active,created_at FROM users ORDER BY created_at DESC LIMIT 500');res.json({users:r.rows.map(publicUser)})}));
 app.post('/api/v1/users',auth,csrf,role('admin'),apiRoute(async(req,res)=>{const email=typeof req.body.email==='string'?req.body.email.trim().toLowerCase():'',roleName=req.body.role;if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254)return sendError(res,400,'INVALID_EMAIL','Enter a valid email address.');if(!ROLES.has(roleName))return sendError(res,400,'INVALID_ROLE','Choose admin, operator or viewer.');let h;try{h=await makePasswordHash(req.body.password)}catch(e){return sendError(res,400,'INVALID_PASSWORD',e.message)}const id=crypto.randomUUID();try{const r=await pool.query('INSERT INTO users(id,email,password_hash,role) VALUES($1,$2,$3,$4) RETURNING id,email,role,active,created_at',[id,email,h,roleName]);await audit(pool,req,'user.create','user',id,{email,role:roleName});res.status(201).json({user:publicUser(r.rows[0])})}catch(e){if(e.code==='23505')return sendError(res,409,'EMAIL_EXISTS','A user with this email already exists.');throw e}}));
 app.patch('/api/v1/users/:id',auth,csrf,role('admin'),apiRoute(async(req,res)=>{const b=req.body||{},hr=Object.hasOwn(b,'role'),ha=Object.hasOwn(b,'active'),hp=Object.hasOwn(b,'password');if(!hr&&!ha&&!hp)return sendError(res,400,'NO_CHANGES','Provide role, active or password.');if(hr&&!ROLES.has(b.role))return sendError(res,400,'INVALID_ROLE','Choose admin, operator or viewer.');if(ha&&typeof b.active!=='boolean')return sendError(res,400,'INVALID_ACTIVE','active must be boolean.');if(wouldLockOutSelf(req.user.id,req.params.id,b))return sendError(res,409,'SELF_LOCKOUT','You cannot demote or disable your own administrator account.');let h=null;if(hp){try{h=await makePasswordHash(b.password)}catch(e){return sendError(res,400,'INVALID_PASSWORD',e.message)}}const c=await pool.connect();try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(742019384)');const f=await c.query('SELECT id,role,active FROM users WHERE id=$1 FOR UPDATE',[req.params.id]);if(!f.rows.length){await c.query('ROLLBACK');return sendError(res,404,'USER_NOT_FOUND','User not found.')}const u=f.rows[0],r=hr?b.role:u.role,a=ha?b.active:u.active;if(u.role==='admin'&&u.active&&(r!=='admin'||!a)){const n=await c.query("SELECT COUNT(*)::int AS n FROM users WHERE role='admin' AND active=TRUE");if(Number(n.rows[0].n)<=1){await c.query('ROLLBACK');return sendError(res,409,'LAST_ADMIN','At least one active administrator must remain.')}}const updated=await c.query('UPDATE users SET role=$2,active=$3,password_hash=COALESCE($4,password_hash),updated_at=NOW() WHERE id=$1 RETURNING id,email,role,active,created_at',[req.params.id,r,a,h]);if(!a||h)await c.query('DELETE FROM sessions WHERE user_id=$1',[req.params.id]);await c.query('COMMIT');await audit(pool,req,'user.update','user',req.params.id,{role:hr?r:undefined,active:ha?a:undefined,passwordReset:!!h});res.json({user:publicUser(updated.rows[0])})}catch(e){await c.query('ROLLBACK').catch(()=>{});throw e}finally{c.release()}}));
 app.get('/api/v1/audit-logs',auth,role('admin'),apiRoute(async(req,res)=>{const n=Number.parseInt(req.query.limit,10),limit=Number.isFinite(n)?Math.max(1,Math.min(n,200)):50,r=await pool.query('SELECT a.id,a.action,a.target_type,a.target_id,a.detail,a.ip_address,a.created_at,u.email AS actor_email FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT $1',[limit]);res.json({events:r.rows.map(x=>({id:x.id,action:x.action,targetType:x.target_type,targetId:x.target_id,detail:x.detail,ipAddress:x.ip_address,createdAt:x.created_at,actorEmail:x.actor_email}))})}));

 app.get('/api/v1/store/apps',apiRoute(async(_req,res)=>{
  const r=await pool.query("SELECT a.id,a.slug,a.name,a.tagline,a.description,a.category,a.icon_url,a.website_url,a.updated_at,COUNT(DISTINCT rel.id)::int AS release_count,MAX(rel.published_at) AS latest_published_at FROM software_apps a LEFT JOIN app_releases rel ON rel.app_id=a.id AND rel.status='published' WHERE a.status='published' GROUP BY a.id ORDER BY a.featured DESC,a.name ASC LIMIT 100");
  res.json({apps:r.rows.map(a=>({id:a.id,slug:a.slug,name:a.name,tagline:a.tagline,description:a.description,category:a.category,iconUrl:a.icon_url,websiteUrl:a.website_url,releaseCount:a.release_count,updatedAt:a.updated_at,latestPublishedAt:a.latest_published_at}))});
 }));
 app.get('/api/v1/store/apps/:slug',apiRoute(async(req,res)=>{
  const a=await pool.query("SELECT id,slug,name,tagline,description,category,icon_url,website_url,updated_at FROM software_apps WHERE slug=$1 AND status='published' LIMIT 1",[req.params.slug]);
  if(!a.rows.length)return sendError(res,404,'APP_NOT_FOUND','App not found.');
  const releases=await pool.query("SELECT id,version,platform,package_url,checksum,release_notes,published_at FROM app_releases WHERE app_id=$1 AND status='published' ORDER BY published_at DESC LIMIT 50",[a.rows[0].id]);
  res.json({app:{id:a.rows[0].id,slug:a.rows[0].slug,name:a.rows[0].name,tagline:a.rows[0].tagline,description:a.rows[0].description,category:a.rows[0].category,iconUrl:a.rows[0].icon_url,websiteUrl:a.rows[0].website_url,updatedAt:a.rows[0].updated_at},releases:releases.rows.map(x=>({id:x.id,version:x.version,platform:x.platform,downloadUrl:x.package_url,checksum:x.checksum,releaseNotes:x.release_notes,publishedAt:x.published_at}))});
 }));
 app.get('/api/v1/admin/apps',auth,role('admin','operator'),apiRoute(async(_req,res)=>{
  const r=await pool.query("SELECT a.id,a.slug,a.name,a.tagline,a.description,a.category,a.status,a.icon_url,a.website_url,a.created_at,a.updated_at,COUNT(rel.id)::int AS release_count FROM software_apps a LEFT JOIN app_releases rel ON rel.app_id=a.id GROUP BY a.id ORDER BY a.updated_at DESC LIMIT 200");
  res.json({apps:r.rows.map(a=>({id:a.id,slug:a.slug,name:a.name,tagline:a.tagline,description:a.description,category:a.category,status:a.status,iconUrl:a.icon_url,websiteUrl:a.website_url,createdAt:a.created_at,updatedAt:a.updated_at,releaseCount:a.release_count}))});
 }));
 app.post('/api/v1/admin/apps',auth,csrf,role('admin'),apiRoute(async(req,res)=>{
  const b=req.body||{},name=typeof b.name==='string'?b.name.trim():'',slug=typeof b.slug==='string'?b.slug.trim().toLowerCase():'',category=typeof b.category==='string'?b.category.trim():'Utilities',tagline=typeof b.tagline==='string'?b.tagline.trim():'',description=typeof b.description==='string'?b.description.trim():'';
  if(name.length<2||name.length>100||!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)||slug.length>80||description.length>5000||tagline.length>180)return sendError(res,400,'INVALID_APP','Provide a valid name, URL slug, tagline and description.');
  const optionalUrl=v=>{if(v===undefined||v===null||v==='')return null;try{const u=new URL(v);return u.protocol==='https:'?u.toString():null}catch(_){return null}};
  const iconUrl=optionalUrl(b.iconUrl),websiteUrl=optionalUrl(b.websiteUrl);
  if((b.iconUrl&&!iconUrl)||(b.websiteUrl&&!websiteUrl))return sendError(res,400,'INVALID_URL','Icon and website URLs must use HTTPS.');
  const id=crypto.randomUUID();
  try{
   const r=await pool.query("INSERT INTO software_apps(id,slug,name,tagline,description,category,status,icon_url,website_url,created_by) VALUES($1,$2,$3,$4,$5,$6,'draft',$7,$8,$9) RETURNING id,slug,name,tagline,description,category,status,icon_url,website_url,created_at,updated_at",[id,slug,name,tagline,description,category||'Utilities',iconUrl,websiteUrl,req.user.id]);
   await audit(pool,req,'app.create','app',id,{slug,name});
   const a=r.rows[0];res.status(201).json({app:{id:a.id,slug:a.slug,name:a.name,tagline:a.tagline,description:a.description,category:a.category,status:a.status,iconUrl:a.icon_url,websiteUrl:a.website_url,createdAt:a.created_at,updatedAt:a.updated_at}});
  }catch(e){if(e.code==='23505')return sendError(res,409,'SLUG_EXISTS','An app with this slug already exists.');throw e}
 }));
 app.post('/api/v1/admin/apps/:id/releases',auth,csrf,role('admin'),apiRoute(async(req,res)=>{
  const b=req.body||{},version=typeof b.version==='string'?b.version.trim():'',platform=typeof b.platform==='string'?b.platform.trim().toLowerCase():'',packageUrl=typeof b.downloadUrl==='string'?b.downloadUrl.trim():'',checksum=typeof b.checksum==='string'?b.checksum.trim().toLowerCase():'',releaseNotes=typeof b.releaseNotes==='string'?b.releaseNotes.trim():'';
  if(!/^v?\d+\.\d+\.\d+(?:[-+][0-9a-z.-]+)?$/i.test(version)||!['windows','macos','linux','android','ios','web','source'].includes(platform)||releaseNotes.length>10000)return sendError(res,400,'INVALID_RELEASE','Provide a semantic version, supported platform and release notes.');
  let u;try{u=new URL(packageUrl)}catch(_){return sendError(res,400,'INVALID_DOWNLOAD_URL','Download URL must be HTTPS.')}
  if(u.protocol!=='https:'||u.username||u.password)return sendError(res,400,'INVALID_DOWNLOAD_URL','Download URL must be HTTPS and cannot contain credentials.');
  if(checksum&&!/^[a-f0-9]{64}$/.test(checksum))return sendError(res,400,'INVALID_CHECKSUM','Checksum must be a SHA-256 hex digest.');
  const app=await pool.query("SELECT id FROM software_apps WHERE id=$1",[req.params.id]);if(!app.rows.length)return sendError(res,404,'APP_NOT_FOUND','App not found.');
  const id=crypto.randomUUID(),status=b.publish===true?'published':'draft';
  const r=await pool.query("INSERT INTO app_releases(id,app_id,version,platform,package_url,checksum,release_notes,status,published_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $8='published' THEN NOW() ELSE NULL END,$9) RETURNING id,version,platform,package_url,checksum,release_notes,status,published_at",[id,req.params.id,version,platform,u.toString(),checksum||null,releaseNotes,status,req.user.id]);
  await pool.query('UPDATE software_apps SET updated_at=NOW() WHERE id=$1',[req.params.id]);await audit(pool,req,'app.release.create','release',id,{appId:req.params.id,version,platform,status});
  const x=r.rows[0];res.status(201).json({release:{id:x.id,version:x.version,platform:x.platform,downloadUrl:x.package_url,checksum:x.checksum,releaseNotes:x.release_notes,status:x.status,publishedAt:x.published_at}});
 }));
 app.post('/api/v1/admin/apps/:id/publish',auth,csrf,role('admin'),apiRoute(async(req,res)=>{
  const c=await pool.connect();try{await c.query('BEGIN');const a=await c.query("SELECT id,slug FROM software_apps WHERE id=$1 FOR UPDATE",[req.params.id]);if(!a.rows.length){await c.query('ROLLBACK');return sendError(res,404,'APP_NOT_FOUND','App not found.')}const count=await c.query("SELECT COUNT(*)::int AS n FROM app_releases WHERE app_id=$1 AND status='published'",[req.params.id]);if(Number(count.rows[0].n)<1){await c.query('ROLLBACK');return sendError(res,409,'RELEASE_REQUIRED','Publish at least one release before publishing the app.')}await c.query("UPDATE software_apps SET status='published',updated_at=NOW() WHERE id=$1",[req.params.id]);await c.query('COMMIT');await audit(pool,req,'app.publish','app',req.params.id,{slug:a.rows[0].slug});res.json({published:true,slug:a.rows[0].slug})}catch(e){await c.query('ROLLBACK').catch(()=>{});throw e}finally{c.release()}
 }));

 app.use('/api/',(_req,res)=>sendError(res,404,'ROUTE_NOT_FOUND','API route not found.'));
 app.get('/',(_req,res)=>res.sendFile(path.join(__dirname,'public','store.html')));
 app.get('/admin',(_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
 app.get('/admin/studio',(_req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
 app.use(express.static(path.join(__dirname,'public'),{index:'index.html',maxAge:env.NODE_ENV==='production'?'1h':0}));
 app.use((_req,res)=>res.status(404).send('Not found'));
 app.use((e,req,res,_next)=>{const status=Number.isInteger(e.status)?e.status:500;if(status>=500)console.error(JSON.stringify({event:'request_failed',requestId:req.id,status,code:e.code||'INTERNAL_ERROR',message:e.message}));if(res.headersSent)return res.end();sendError(res,status,e.code||'REQUEST_FAILED',status===500?'An unexpected server error occurred.':e.message)});
 return app;
}
async function migrate(pool,env){
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  await client.query('SELECT pg_advisory_xact_lock($1)',[742019385]);
  await client.query("CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')),active BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
  await client.query("CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf_token TEXT NOT NULL,expires_at TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
  await client.query('CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id)');
  await client.query("CREATE TABLE IF NOT EXISTS audit_logs(id BIGSERIAL PRIMARY KEY,actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,action TEXT NOT NULL,target_type TEXT,target_id TEXT,detail JSONB NOT NULL DEFAULT '{}'::jsonb,ip_address INET,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
  await client.query('CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs(created_at DESC)');
  await client.query("CREATE TABLE IF NOT EXISTS software_apps(id TEXT PRIMARY KEY,slug TEXT NOT NULL UNIQUE,name TEXT NOT NULL,tagline TEXT NOT NULL DEFAULT '',description TEXT NOT NULL DEFAULT '',category TEXT NOT NULL DEFAULT 'Utilities',status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','archived')),icon_url TEXT,website_url TEXT,featured BOOLEAN NOT NULL DEFAULT FALSE,created_by TEXT REFERENCES users(id) ON DELETE SET NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())");
  await client.query("CREATE TABLE IF NOT EXISTS app_releases(id TEXT PRIMARY KEY,app_id TEXT NOT NULL REFERENCES software_apps(id) ON DELETE CASCADE,version TEXT NOT NULL,platform TEXT NOT NULL CHECK(platform IN ('windows','macos','linux','android','ios','web','source')),package_url TEXT NOT NULL,checksum TEXT,release_notes TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','withdrawn')),published_at TIMESTAMPTZ,created_by TEXT REFERENCES users(id) ON DELETE SET NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(app_id,version,platform))");
  await client.query("CREATE INDEX IF NOT EXISTS software_apps_public_idx ON software_apps(status,featured,updated_at DESC)");
  await client.query("CREATE INDEX IF NOT EXISTS app_releases_public_idx ON app_releases(app_id,status,published_at DESC)");

  await client.query('DELETE FROM sessions WHERE expires_at<=NOW()');
  const count=await client.query('SELECT COUNT(*)::int AS count FROM users');
  if(Number(count.rows[0].count)>0){await client.query('COMMIT');return}
  const email=String(env.BOOTSTRAP_ADMIN_EMAIL||'').trim().toLowerCase();
  const password=String(env.BOOTSTRAP_ADMIN_PASSWORD||'');
  if(!email||!password)throw Error('No admin exists. Set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD for the first start.');
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))throw Error('BOOTSTRAP_ADMIN_EMAIL is invalid.');
  const hash=await makePasswordHash(password);
  await client.query('INSERT INTO users(id,email,password_hash,role) VALUES($1,$2,$3,$4)',[crypto.randomUUID(),email,hash,'admin']);
  await client.query('COMMIT');
  console.info(JSON.stringify({event:'bootstrap_admin_created',email}));
 }catch(e){await client.query('ROLLBACK').catch(()=>{});throw e}
 finally{client.release()}
}
function validateConfig(env){
 if(!env.DATABASE_URL||!String(env.DATABASE_URL).trim())throw Error('DATABASE_URL is required.');
 if(!env.SESSION_SECRET||env.SESSION_SECRET.length<32)throw Error('SESSION_SECRET must be at least 32 characters.');
 if(env.NODE_ENV==='production'){let u;try{u=new URL(env.APP_ORIGIN||'')}catch(_){throw Error('APP_ORIGIN must be the exact public HTTPS origin.')}if(u.protocol!=='https:'||u.origin!==env.APP_ORIGIN)throw Error('APP_ORIGIN must be HTTPS without a trailing slash.')}
 const poolMax=env.PG_POOL_MAX===undefined||env.PG_POOL_MAX===''?10:Number(env.PG_POOL_MAX);
 if(!Number.isInteger(poolMax)||poolMax<1||poolMax>50)throw Error('PG_POOL_MAX must be an integer from 1 to 50.');
 return {poolMax};
}
async function start(){
 const env=process.env,config=validateConfig(env);
 const pool=new Pool({connectionString:env.DATABASE_URL,max:config.poolMax,idleTimeoutMillis:30000,connectionTimeoutMillis:10000,application_name:'server-management-panel'});
 try{await migrate(pool,env);const server=createApp(pool,env).listen(Number(env.PORT||10000),'0.0.0.0',()=>console.info(JSON.stringify({event:'server_started',port:Number(env.PORT||10000),version:VERSION})));const cleanupTimer=setInterval(()=>pool.query('DELETE FROM sessions WHERE expires_at<=NOW()').catch(e=>console.error(JSON.stringify({event:'session_cleanup_failed',message:e.message}))),60*60*1000);cleanupTimer.unref();let closing=false;function shutdown(signal){if(closing)return;closing=true;clearInterval(cleanupTimer);console.info(JSON.stringify({event:'shutdown_started',signal}));server.close(()=>pool.end().then(()=>process.exit(0)));setTimeout(()=>process.exit(1),10000).unref()}process.on('SIGTERM',()=>shutdown('SIGTERM'));process.on('SIGINT',()=>shutdown('SIGINT'))}catch(e){await pool.end().catch(()=>{});throw e}
}
if(require.main===module)start().catch(e=>{console.error(JSON.stringify({event:'startup_failed',message:e.message}));process.exitCode=1});
module.exports={createApp,passwordMatches,tokenHash,allowlist,trustedOrigin,normalizeService,makePasswordHash,wouldLockOutSelf,validateConfig};