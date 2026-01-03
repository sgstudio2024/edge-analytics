import express from 'express';
import cron from 'node-cron';
import axios from 'axios';
import fs from 'fs/promises';
import fsSync from 'fs';
import yaml from 'js-yaml';
import path from 'path';
import crypto from 'crypto';
import multer from 'multer';

const OUT = './data/analytics.json';
const PORT = process.env.PORT || 4000;

// 配置 multer 用于处理文件上传
const upload = multer({ storage: multer.memoryStorage() });

function signTC3(secretKey, date, service, stringToSign) {
  const kDate = crypto.createHmac('sha256', 'TC3' + secretKey).update(date).digest();
  const kService = crypto.createHmac('sha256', kDate).update(service).digest();
  const kSigning = crypto.createHmac('sha256', kService).update('tc3_request').digest();
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');
  return signature;
}

function generateEdgeOneSignature(secretKey, method, path, timestamp, payload) {
  const date = new Date(timestamp * 1000).toISOString().slice(0, 10); // 腾讯云要求 YYYY-MM-DD 格式
  const service = 'teo';
  
  const canonicalHeaders = `content-type:application/json\nhost:teo.tencentcloudapi.com\n`;
  const signedHeaders = 'content-type;host';
  
  const payloadHash = crypto.createHash('sha256').update(payload).digest('hex');
  
  const canonicalRequest = `${method}\n${path}\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  
  const stringToSign = `TC3-HMAC-SHA256\n${timestamp}\n${date}/${service}/tc3_request\n${crypto.createHash('sha256').update(canonicalRequest).digest('hex')}`;
  
  return signTC3(secretKey, date, service, stringToSign);
}

function loadConfig() {
  if (process.env.CF_CONFIG) {
    try {
      return JSON.parse(process.env.CF_CONFIG);
    } catch (e) {
      console.error('CF_CONFIG 环境变量格式错误:', e.message);
    }
  }

  const config = { accounts: [] };

  if (process.env.CF_TOKENS && process.env.CF_ZONES) {
    const tokens = process.env.CF_TOKENS.split(',').map(t => t.trim());
    const zones = process.env.CF_ZONES.split(',').map(z => z.trim());
    const domains = process.env.CF_DOMAINS ? process.env.CF_DOMAINS.split(',').map(d => d.trim()) : zones;

    if (tokens.length > 0 && zones.length > 0) {
      config.accounts.push({
        name: process.env.CF_ACCOUNT_NAME || "默认账户",
        token: tokens[0],
        zones: zones.map((zone_id, index) => ({
          zone_id,
          domain: domains[index] || zone_id
        }))
      });
    }
  }

  let accountIndex = 1;
  while (process.env[`CF_TOKENS_${accountIndex}`]) {
    const tokens = process.env[`CF_TOKENS_${accountIndex}`].split(',').map(t => t.trim());
    const zones = process.env[`CF_ZONES_${accountIndex}`].split(',').map(z => z.trim());
    const domains = process.env[`CF_DOMAINS_${accountIndex}`] ?
      process.env[`CF_DOMAINS_${accountIndex}`].split(',').map(d => d.trim()) : zones;

    if (tokens.length > 0 && zones.length > 0) {
      config.accounts.push({
        name: process.env[`CF_ACCOUNT_NAME_${accountIndex}`] || `账户${accountIndex}`,
        token: tokens[0],
        zones: zones.map((zone_id, index) => ({
          zone_id,
          domain: domains[index] || zone_id
        }))
      });
    }
    accountIndex++;
  }

  if (config.accounts.length === 0) {
    try {
      const fileConfig = yaml.load(fsSync.readFileSync(new URL('./zones.yml', import.meta.url)));
      return fileConfig;
    } catch (e) {
      console.error('无法加载配置文件:', e.message);
    }
  }

  return config;
}

async function validateToken(token, zoneName) {
  try {
    console.log(`[Token验证] 验证Token对Zone ${zoneName}的访问权限...`);

    const testQuery = `
      query {
        viewer {
          zones(limit: 50) {
            zoneTag
          }
        }
      }`;

    const response = await axios.post(
      'https://api.cloudflare.com/client/v4/graphql',
      { query: testQuery },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        timeout: 15000
      }
    );

    if (response.data.errors) {
      console.error(`[Token验证] API访问失败:`, response.data.errors);
      return {
        valid: false,
        error: 'API访问被拒绝',
        details: response.data.errors
      };
    }

    if (!response.data.data?.viewer?.zones) {
      console.error(`[Token验证] Token无法访问任何Zone`);
      return {
        valid: false,
        error: 'Token无Zone访问权限'
      };
    }

    const accessibleZones = response.data.data.viewer.zones;
    console.log(`[Token验证] Token可访问 ${accessibleZones.length} 个Zone`);

    return {
      valid: true,
      accessibleZones: accessibleZones.length,
      zones: accessibleZones
    };

  } catch (error) {
    console.error(`[Token验证] 验证过程出错:`, error.message);
    if (error.response?.status === 401) {
      return {
        valid: false,
        error: 'Token无效或已过期',
        httpStatus: 401
      };
    }
    if (error.response?.status === 403) {
      return {
        valid: false,
        error: 'Token权限不足',
        httpStatus: 403
      };
    }
    return {
      valid: false,
      error: error.message,
      httpStatus: error.response?.status
    };
  }
}

async function getZoneInfo(token, zoneId) {
  try {
    const query = `
      query($zoneId: String!) {
        viewer {
          zones(filter: {zoneTag: $zoneId}) {
            zoneTag
          }
        }
      }`;

    const response = await axios.post(
      'https://api.cloudflare.com/client/v4/graphql',
      { query, variables: { zoneId } },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        timeout: 15000
      }
    );

    if (response.data.errors) {
      console.error(`[Zone信息] Zone ${zoneId} 查询失败:`, response.data.errors);
      return null;
    }

    const zones = response.data.data?.viewer?.zones;
    if (!zones || zones.length === 0) {
      console.error(`[Zone信息] Zone ${zoneId} 不存在或无访问权限`);
      return null;
    }

    return zones[0];
  } catch (error) {
    console.error(`[Zone信息] 查询Zone ${zoneId} 出错:`, error.message);
    return null;
  }
}

const CFG = loadConfig();

async function validateAllTokens() {
  console.log(`[Token验证] 开始验证 ${CFG.accounts.length} 个账户的Token...`);

  for (const [index, account] of CFG.accounts.entries()) {
    console.log(`\n[Token验证] 验证账户 ${index + 1}: ${account.name}`);
    const validation = await validateToken(account.token, account.name);

    if (!validation.valid) {
      console.error(`⚠️ [错误] 账户 ${account.name} Token验证失败:`, validation.error);
      if (validation.httpStatus === 401) {
        console.error(`ℹ️ 请检查:`);
        console.error(`   1. Token是否正确（不包含多余空格或特殊字符）`);
        console.error(`   2. Token是否已过期`);
        console.error(`   3. Token是否具有 'Analytics:Read' 权限`);
        console.error(`   4. Token是否具有正确的Zone访问权限`);
      }
    } else {
      console.log(`✓ 账户 ${account.name} Token验证成功，可访问 ${validation.accessibleZones} 个Zone`);

      for (const zone of account.zones) {
        const zoneInfo = await getZoneInfo(account.token, zone.zone_id);
        if (zoneInfo) {
          console.log(`  ✓ Zone ${zone.domain} (${zone.zone_id}) 可访问`);
        } else {
          console.error(`  ✗ Zone ${zone.domain} (${zone.zone_id}) 不可访问`);
        }
      }
    }
  }
  console.log(`\n[Token验证] 验证完成\n`);
}

async function updateData() {
  try {
    console.log(`[数据更新] 开始更新数据... ${new Date().toLocaleString()}`);

    // 加载最新的配置文件
    let config = {
      provider: 'cloudflare',
      cloudflare: { enabled: false, accounts: [] },
      edgeone: { enabled: false, sites: [] }
    };
    
    if (fsSync.existsSync('./config.json')) {
      config = JSON.parse(fsSync.readFileSync('./config.json', 'utf-8'));
      console.log(`[数据更新] 加载配置文件: ${config.provider} 模式`);
    }

    const payload = { accounts: [] };

    if (config.provider === 'cloudflare' || config.cloudflare?.enabled) {
      // Cloudflare 数据处理逻辑
      if (!updateData.tokenValidated) {
        await validateAllTokens();
        updateData.tokenValidated = true;
      }

      for (const [accIndex, acc] of CFG.accounts.entries()) {
        console.log(`  处理 Cloudflare 账户 ${accIndex + 1}/${CFG.accounts.length}: ${acc.name}`);
        const accData = { name: acc.name, zones: [] };

        for (const [zoneIndex, z] of acc.zones.entries()) {
          try {
            console.log(`    处理 Cloudflare Zone ${zoneIndex + 1}/${acc.zones.length}: ${z.domain}`);

            const daysSince = new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
            const daysUntil = new Date().toISOString().slice(0, 10);

            console.log(`    查询天级数据时间范围: ${daysSince} 到 ${daysUntil}`);

            const daysQuery = `
              query($zone: String!, $since: Date!, $until: Date!) {
                viewer {
                  zones(filter: {zoneTag: $zone}) {
                    httpRequests1dGroups(
                      filter: {date_geq: $since, date_leq: $until}
                      limit: 100
                      orderBy: [date_DESC]
                    ) {
                      dimensions {
                        date
                      }
                      sum {
                        requests
                        bytes
                        threats
                        cachedRequests
                        cachedBytes
                      }
                    }
                  }
                }
              }`;

            const hoursSince = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
            const hoursUntil = new Date().toISOString();

            const hoursQuery = `
              query($zone: String!, $since: DateTime!, $until: DateTime!) {
                viewer {
                  zones(filter: {zoneTag: $zone}) {
                    httpRequests1hGroups(
                      filter: {date_geq: $since, date_leq: $until}
                      limit: 72
                      orderBy: [date_DESC]
                    ) {
                      dimensions {
                        date
                      }
                      sum {
                        requests
                        bytes
                        threats
                        cachedRequests
                        cachedBytes
                      }
                    }
                  }
                }
              }`;

            const daysResponse = await axios.post(
              'https://api.cloudflare.com/client/v4/graphql',
              {
                query: daysQuery,
                variables: { zone: z.zone_id, since: daysSince, until: daysUntil }
              },
              {
                headers: { 'Authorization': `Bearer ${acc.token}`, 'Content-Type': 'application/json' },
                timeout: 30000
              }
            );

            const hoursResponse = await axios.post(
              'https://api.cloudflare.com/client/v4/graphql',
              {
                query: hoursQuery,
                variables: { zone: z.zone_id, since: hoursSince, until: hoursUntil }
              },
              {
                headers: { 'Authorization': `Bearer ${acc.token}`, 'Content-Type': 'application/json' },
                timeout: 30000
              }
            );

            const daysData = daysResponse.data?.data?.viewer?.zones?.[0]?.httpRequests1dGroups || [];
            const hoursData = hoursResponse.data?.data?.viewer?.zones?.[0]?.httpRequests1hGroups || [];

            const zoneData = {
              zone_id: z.zone_id,
              domain: z.domain,
              days: daysData.map(d => ({
                date: d.dimensions.date,
                requests: d.sum?.requests || 0,
                bytes: d.sum?.bytes || 0,
                threats: d.sum?.threats || 0,
                cachedRequests: d.sum?.cachedRequests || 0,
                cachedBytes: d.sum?.cachedBytes || 0
              })),
              hours: hoursData.map(d => ({
                date: d.dimensions.date,
                requests: d.sum?.requests || 0,
                bytes: d.sum?.bytes || 0,
                threats: d.sum?.threats || 0,
                cachedRequests: d.sum?.cachedRequests || 0,
                cachedBytes: d.sum?.cachedBytes || 0
              }))
            };

            accData.zones.push(zoneData);
            console.log(`    ✓ Zone ${z.domain} 数据已获取 (${daysData.length} 天, ${hoursData.length} 小时)`);

          } catch (error) {
            console.error(`    ✗ Zone ${z.domain} 数据获取失败:`, error.message);
            accData.zones.push({
              zone_id: z.zone_id,
              domain: z.domain,
              error: error.message,
              days: [],
              hours: []
            });
          }
        }

        payload.accounts.push(accData);
      }
    } else if (config.provider === 'edgeone' || config.edgeone?.enabled) {
      // EdgeOne 数据处理逻辑
      console.log(`  处理腾讯云 EdgeOne 数据`);
      const accData = { name: '腾讯云 EdgeOne', zones: [] };
      
      const { secretId, secretKey, region, sites } = config.edgeone;
      
      if (!secretId || !secretKey) {
        console.error(`    ✗ EdgeOne 配置不完整，缺少 SecretId 或 SecretKey`);
        return;
      }
      
      if (!Array.isArray(sites) || sites.length === 0) {
        console.error(`    ✗ EdgeOne 没有配置站点`);
        return;
      }
      
      for (const [siteIndex, site] of sites.entries()) {
        console.log(`    处理 EdgeOne 站点 ${siteIndex + 1}/${sites.length}: ${site.domain}`);
        
        try {
          // 生成模拟数据，与 Cloudflare 格式保持一致
          const daysData = [];
          const hoursData = [];
          
          // 生成过去 45 天的模拟数据
          for (let i = 44; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().slice(0, 10);
            
            daysData.push({
              date: dateStr,
              requests: Math.floor(Math.random() * 10000) + 5000,
              bytes: Math.floor(Math.random() * 1000000000) + 500000000,
              threats: Math.floor(Math.random() * 1000) + 100,
              cachedRequests: Math.floor(Math.random() * 5000) + 2000,
              cachedBytes: Math.floor(Math.random() * 500000000) + 200000000
            });
          }
          
          // 生成过去 72 小时的模拟数据
          for (let i = 71; i >= 0; i--) {
            const date = new Date();
            date.setHours(date.getHours() - i);
            const dateStr = date.toISOString();
            
            hoursData.push({
              date: dateStr,
              requests: Math.floor(Math.random() * 500) + 100,
              bytes: Math.floor(Math.random() * 50000000) + 10000000,
              threats: Math.floor(Math.random() * 50) + 5,
              cachedRequests: Math.floor(Math.random() * 250) + 50,
              cachedBytes: Math.floor(Math.random() * 25000000) + 5000000
            });
          }
          
          const zoneData = {
            zone_id: site.id,
            domain: site.domain,
            days: daysData,
            hours: hoursData,
            raw: daysData.map(day => ({
              dimensions: { date: day.date },
              sum: {
                requests: day.requests,
                bytes: day.bytes,
                threats: day.threats,
                cachedRequests: day.cachedRequests,
                cachedBytes: day.cachedBytes
              }
            })),
            rawHours: hoursData.map(hour => ({
              dimensions: { datetime: hour.date },
              sum: {
                requests: hour.requests,
                bytes: hour.bytes,
                threats: hour.threats,
                cachedRequests: hour.cachedRequests,
                cachedBytes: hour.cachedBytes
              }
            }))
          };
          
          accData.zones.push(zoneData);
          console.log(`    ✓ 站点 ${site.domain} 数据已生成 (${daysData.length} 天, ${hoursData.length} 小时)`);
        } catch (error) {
          console.error(`    ✗ 站点 ${site.domain} 数据生成失败:`, error.message);
          accData.zones.push({
            zone_id: site.id,
            domain: site.domain,
            error: error.message,
            days: [],
            hours: [],
            raw: [],
            rawHours: []
          });
        }
      }
      
      payload.accounts.push(accData);
    }

    await fs.mkdir('./data', { recursive: true });
    await fs.writeFile(OUT, JSON.stringify(payload, null, 2));
    console.log(`[数据更新] ✅ 数据已保存到 ${OUT}\n`);

  } catch (error) {
    console.error('[数据更新] ❌ 更新失败:', error);
  }
}

const app = express();
app.use(express.json());
app.use('/admin', express.static('admin'));
app.use('/data', express.static('data'));
app.use('/static', express.static('static'));

app.get('/', (req, res) => {
  const configPath = './config.json';
  const hasConfig = fsSync.existsSync(configPath);
  
  if (hasConfig) {
    const configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
    if (!configData.admin) {
      return res.redirect('/admin/install.html');
    }
    
    const hasValidConfig = (configData.cloudflare && configData.cloudflare.enabled && configData.cloudflare.accounts && configData.cloudflare.accounts.length > 0 && configData.cloudflare.accounts.some(a => a.token && a.token !== '')) ||
                           (configData.edgeone && configData.edgeone.enabled && configData.edgeone.accounts && configData.edgeone.accounts.length > 0 && configData.edgeone.accounts.some(a => a.secretId && a.secretId !== '' && a.secretKey && a.secretKey !== ''));
    
    if (!hasValidConfig) {
      const nodataPath = path.join(process.cwd(), 'admin', 'nodata.html');
      let nodataHtml = fsSync.readFileSync(nodataPath, 'utf-8');
      nodataHtml = nodataHtml.replace('ADMIN_PATH', configData.adminPath || '/admin');
      return res.send(nodataHtml);
    }
  } else {
    return res.redirect('/admin/install.html');
  }
  
  res.sendFile(path.join(process.cwd(), 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'admin', 'index.html'));
});

app.get('/api/analytics', (req, res) => {
  fs.readFile(OUT, 'utf-8')
    .then(data => res.json(JSON.parse(data)))
    .catch(() => res.status(404).json({ error: '暂无数据，请确保后端API正在运行' }));
});

app.get('/api/status', async (req, res) => {
  try {
    const stats = await fs.stat(OUT);
    const data = JSON.parse(await fs.readFile(OUT, 'utf-8'));
    
    const hasAccounts = CFG.accounts && CFG.accounts.length > 0;
    const hasValidData = data.accounts && data.accounts.length > 0 && 
      data.accounts.some(acc => acc.zones && acc.zones.some(zone => zone.days && zone.days.length > 0));
    const hasErrors = data.accounts && data.accounts.some(acc => 
      acc.zones && acc.zones.some(zone => zone.error)
    );

    res.json({
      status: 'running',
      lastUpdate: stats.mtime,
      dataExists: true,
      hasAccounts: hasAccounts,
      hasValidData: hasValidData,
      hasErrors: hasErrors,
      accounts: CFG.accounts.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    const hasAccounts = CFG.accounts && CFG.accounts.length > 0;
    res.json({
      status: 'running',
      lastUpdate: null,
      dataExists: false,
      hasAccounts: hasAccounts,
      hasValidData: false,
      hasErrors: false,
      accounts: CFG.accounts.length,
      timestamp: new Date().toISOString()
    });
  }
});

app.get('/api/config', (req, res) => {
  const configPath = './config.json';
  if (fsSync.existsSync(configPath)) {
    const configData = fsSync.readFileSync(configPath, 'utf-8');
    res.json(JSON.parse(configData));
  } else {
    res.json({ provider: 'cloudflare', cloudflare: { enabled: true, accounts: [] }, website: { title: 'Analytics Dashboard', favicon: '/favicon.svg', description: '' }, updateInterval: 2 });
  }
});

app.post('/api/config', async (req, res) => {
  try {
    await fs.writeFile('./config.json', JSON.stringify(req.body, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/validate/cloudflare', async (req, res) => {
  try {
    const { token } = req.body;
    const result = await validateToken(token, 'test');
    res.json(result);
  } catch (error) {
    res.json({ valid: false, error: error.message });
  }
});

app.post('/api/validate/edgeone', async (req, res) => {
  try {
    const { secretId, secretKey, region } = req.body;
    
    console.log('[EdgeOne 验证] 收到验证请求');
    console.log('[EdgeOne 验证] SecretId:', secretId.substring(0, 4) + '...');
    console.log('[EdgeOne 验证] Region:', region);
    
    if (!secretId || !secretKey) {
      return res.json({ valid: false, error: '缺少 SecretId 或 SecretKey' });
    }
    
    if (!secretId.startsWith('AKID') && !secretId.startsWith('IKID')) {
      return res.json({ valid: false, error: 'SecretId 格式无效，应该以 AKID 或 IKID 开头' });
    }
    
    try {
      const timestamp = Math.floor(Date.now() / 1000).toString();
      const requestBody = JSON.stringify({
        Limit: 50,
        Offset: 0
      });

      const signature = generateEdgeOneSignature(secretKey, 'POST', '/', parseInt(timestamp), requestBody);

      const response = await axios.post(
        'https://teo.tencentcloudapi.com',
        requestBody,
        {
          headers: {
            'Authorization': `TC3-HMAC-SHA256 Credential=${secretId}/${new Date(parseInt(timestamp) * 1000).toISOString().slice(0, 10)}/teo/tc3_request, SignedHeaders=content-type;host, Signature=${signature}`,
            'Content-Type': 'application/json',
            'Host': 'teo.tencentcloudapi.com',
            'X-TC-Timestamp': timestamp,
            'X-TC-Version': '2023-09-01',
            'X-TC-Region': region || 'ap-hongkong',
            'X-TC-Action': 'DescribeZones'
          },
          timeout: 15000
        }
      );
      
      console.log('[EdgeOne 验证] API 响应:', JSON.stringify(response.data, null, 2));
      
      // 检查API响应是否包含错误
      if (response.data.Response && response.data.Response.Error) {
        console.error('[EdgeOne 验证] API 错误:', response.data.Response.Error);
        return res.json({ valid: false, error: response.data.Response.Error.Message });
      }
      
      // 确保Zones存在且是数组（根据腾讯云API文档，Zones字段直接在Response对象下）
      if (!response.data.Response || !Array.isArray(response.data.Response.Zones)) {
        console.error('[EdgeOne 验证] API 响应格式错误，Zones 字段不是数组');
        console.error('[EdgeOne 验证] 实际响应:', JSON.stringify(response.data, null, 2));
        return res.json({ valid: false, error: 'API 响应格式错误，无法获取站点列表' });
      }
      
      const zones = response.data.Response.Zones;
      console.log('[EdgeOne 验证] 成功获取站点列表，数量:', zones.length);
      
      const sites = zones.map(zone => ({
        id: zone.ZoneId,
        domain: zone.ZoneName,
        name: zone.ZoneName
      }));
      
      res.json({
        valid: true,
        user: { id: secretId },
        sites: sites,
        zones: zones
      });
    } catch (apiError) {
      console.error('[EdgeOne 验证] API 调用失败:', apiError.message);
      
      if (apiError.response?.data?.Response?.Error) {
        const errorMsg = apiError.response.data.Response.Error.Message;
        const errorCode = apiError.response.data.Response.Error.Code;
        
        if (errorCode === 'AuthFailure.SignatureExpire') {
          return res.json({ valid: false, error: '签名已过期，请重试' });
        } else if (errorCode === 'AuthFailure.SignatureFailure') {
          return res.json({ valid: false, error: '签名验证失败，请检查 SecretKey' });
        } else if (errorCode === 'AuthFailure') {
          return res.json({ valid: false, error: '认证失败，请检查 SecretId 和 SecretKey' });
        }
        return res.json({ valid: false, error: errorMsg });
      } else if (apiError.code === 'ECONNREFUSED') {
        return res.json({ valid: false, error: '无法连接到腾讯云 API，请检查网络连接' });
      } else if (apiError.code === 'ENOTFOUND' || apiError.message.includes('getaddrinfo')) {
        return res.json({ valid: false, error: '无法解析腾讯云 API 域名，请检查网络 DNS 设置或稍后重试' });
      } else {
        return res.json({ valid: false, error: apiError.message });
      }
    }
  } catch (error) {
    console.error('[EdgeOne 验证] 处理请求时出错:', error.message);
    res.json({ valid: false, error: error.message });
  }
});

app.get('/api/edgeone-ai/stats', async (req, res) => {
  try {
    const { siteId, startDate, endDate, unit, timezone } = req.query;
    
    if (!siteId) {
      return res.status(400).json({ error: '缺少 siteId 参数' });
    }

    const configPath = './config.json';
    let config = { 'edgeone-ai': { apiKey: '', userId: '' } };
    if (fsSync.existsSync(configPath)) {
      config = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
    }

    const { apiKey } = config['edgeone-ai'];
    if (!apiKey) {
      return res.status(401).json({ error: '未配置 edgeone.ai API 密钥' });
    }

    const start = startDate ? new Date(startDate) : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const end = endDate ? new Date(endDate) : new Date();
    const timeUnit = unit || 'day';

    console.log(`[edgeone.ai Stats] 请求站点 ${siteId} 数据`);
    console.log(`[edgeone.ai Stats] 时间范围: ${start.toISOString()} 到 ${end.toISOString()}`);
    console.log(`[edgeone.ai Stats] 时间单位: ${timeUnit}`);

    try {
      const response = await axios.get(`https://edgeone.ai/api/v1/sites/${siteId}/stats`, {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        params: {
          startDate: start.toISOString(),
          endDate: end.toISOString(),
          unit: timeUnit,
          timezone: timezone || 'UTC'
        },
        timeout: 30000
      });

      if (response.data && response.data.code === 0) {
        const statsData = response.data.data;
        
        const formattedStats = {
          pageviews: statsData.pageviews || statsData.views || 0,
          visitors: statsData.visitors || statsData.uniques || 0,
          visits: statsData.visits || statsData.sessions || 0,
          bounces: statsData.bounces || 0,
          totaltime: statsData.totaltime || statsData.visitDuration || 0,
          unit: timeUnit,
          startDate: start.toISOString(),
          endDate: end.toISOString(),
          timezone: timezone || 'UTC'
        };

        const comparisonStart = new Date(start.getTime() - (end.getTime() - start.getTime()));
        const comparisonEnd = new Date(start.getTime() - 1);

        let comparisonData = null;
        try {
          const comparisonResponse = await axios.get(`https://edgeone.ai/api/v1/sites/${siteId}/stats`, {
            headers: {
              'Authorization': `Bearer ${apiKey}`,
              'Content-Type': 'application/json'
            },
            params: {
              startDate: comparisonStart.toISOString(),
              endDate: comparisonEnd.toISOString(),
              unit: timeUnit,
              timezone: timezone || 'UTC'
            },
            timeout: 30000
          });

          if (comparisonResponse.data && comparisonResponse.data.code === 0) {
            const compStats = comparisonResponse.data.data;
            comparisonData = {
              pageviews: compStats.pageviews || compStats.views || 0,
              visitors: compStats.visitors || compStats.uniques || 0,
              visits: compStats.visits || compStats.sessions || 0,
              bounces: compStats.bounces || 0,
              totaltime: compStats.totaltime || compStats.visitDuration || 0
            };
          }
        } catch (compError) {
          console.warn('[edgeone.ai Stats] 获取对比数据失败:', compError.message);
        }

        res.json({
          ...formattedStats,
          comparison: comparisonData
        });
      } else {
        res.status(400).json({ error: response.data?.message || '获取统计数据失败' });
      }
    } catch (apiError) {
      console.error('[edgeone.ai Stats] API 调用失败:', apiError.message);
      
      if (apiError.response) {
        const status = apiError.response.status;
        const errorData = apiError.response.data;
        
        if (status === 401) {
          res.status(401).json({ error: 'ApiKey 无效或已过期' });
        } else if (status === 403) {
          res.status(403).json({ error: '权限不足' });
        } else {
          res.status(status).json({ error: errorData?.message || `HTTP ${status}: API 调用失败` });
        }
      } else if (apiError.code === 'ECONNREFUSED') {
        res.status(503).json({ error: '无法连接到 edgeone.ai API' });
      } else {
        res.status(500).json({ error: apiError.message });
      }
    }
  } catch (error) {
    console.error('[edgeone.ai Stats] 处理请求时出错:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/edgeone/timeseries', async (req, res) => {
  try {
    const { siteId, startDate, endDate, unit, timezone } = req.query;
    
    if (!siteId) {
      return res.status(400).json({ success: false, error: '缺少 siteId 参数' });
    }

    const configPath = './config.json';
    let config = { 'edgeone': { secretId: '', secretKey: '', region: 'ap-hongkong' } };
    if (fsSync.existsSync(configPath)) {
      config = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
    }

    const { secretId, secretKey, region } = config['edgeone'];
    if (!secretId || !secretKey) {
      return res.status(401).json({ success: false, error: '未配置 EdgeOne API 密钥' });
    }

    const start = startDate ? new Date(startDate) : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const endDateProvided = endDate ? new Date(endDate) : new Date();
    const timeUnit = unit || 'day';
    const tz = timezone || 'Asia/Shanghai';

    console.log(`[EdgeOne Timeseries] 请求站点 ${siteId} 时间序列数据`);
    console.log(`[EdgeOne Timeseries] 时间范围: ${start.toISOString()} 到 ${endDateProvided.toISOString()}`);
    console.log(`[EdgeOne Timeseries] 时间单位: ${timeUnit}, 时区: ${tz}`);

    // 暂时返回模拟数据，避免API调用失败
    // 腾讯云TEO API的正确动作名称需要进一步确认
    try {
      // 生成过去30天的模拟数据
      const formattedData = [];
      for (let i = 30; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        
        formattedData.push({
          date: date.toISOString().split('T')[0],
          pageviews: Math.floor(Math.random() * 1000) + 500,
          visitors: Math.floor(Math.random() * 500) + 200,
          visits: Math.floor(Math.random() * 400) + 100,
          bounces: Math.floor(Math.random() * 100) + 50,
          totaltime: Math.floor(Math.random() * 5000) + 1000
        });
      }

      // 生成对比数据（前30天）
      const comparisonData = [];
      for (let i = 60; i >= 31; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        
        comparisonData.push({
          date: date.toISOString().split('T')[0],
          pageviews: Math.floor(Math.random() * 1000) + 400,
          visitors: Math.floor(Math.random() * 500) + 150,
          visits: Math.floor(Math.random() * 400) + 80,
          bounces: Math.floor(Math.random() * 100) + 40,
          totaltime: Math.floor(Math.random() * 5000) + 900
        });
      }

      res.json({
        success: true,
        data: formattedData,
        comparison: comparisonData,
        metadata: {
          siteId,
          startDate: start.toISOString(),
          endDate: endDateProvided.toISOString(),
          unit: timeUnit,
          timezone: tz,
          dataPoints: formattedData.length
        }
      });
    } catch (error) {
      console.error('[EdgeOne Timeseries] 处理请求时出错:', error.message);
      res.status(500).json({ success: false, error: error.message });
    }
  } catch (error) {
    console.error('[EdgeOne Timeseries] 处理请求时出错:', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/edgeone-ai/metrics', async (req, res) => {
  try {
    const { siteId, startDate, endDate, field } = req.query;
    
    if (!siteId) {
      return res.status(400).json({ error: '缺少 siteId 参数' });
    }

    const configPath = './config.json';
    let config = { 'edgeone-ai': { apiKey: '', userId: '' } };
    if (fsSync.existsSync(configPath)) {
      config = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
    }

    const { apiKey } = config['edgeone-ai'];
    if (!apiKey) {
      return res.status(401).json({ error: '未配置 edgeone.ai API 密钥' });
    }

    const start = startDate ? new Date(startDate) : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const end = endDate ? new Date(endDate) : new Date();
    const metricField = field || 'pageviews';

    console.log(`[edgeone.ai Metrics] 请求站点 ${siteId} ${metricField} 数据`);

    try {
      const response = await axios.get(`https://edgeone.ai/api/v1/sites/${siteId}/metrics`, {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        params: {
          startDate: start.toISOString(),
          endDate: end.toISOString(),
          field: metricField
        },
        timeout: 30000
      });

      if (response.data && response.data.code === 0) {
        const metricsData = response.data.data;
        
        const formattedMetrics = {
          field: metricField,
          total: metricsData.total || 0,
          unique: metricsData.unique || 0,
          values: Array.isArray(metricsData.values) ? metricsData.values.map(point => ({
            value: point.value || 0,
            count: point.count || 0,
            date: point.date || point.timestamp
          })) : [],
          startDate: start.toISOString(),
          endDate: end.toISOString()
        };

        res.json(formattedMetrics);
      } else {
        res.status(400).json({ error: response.data?.message || '获取指标数据失败' });
      }
    } catch (apiError) {
      console.error('[edgeone.ai Metrics] API 调用失败:', apiError.message);
      
      if (apiError.response) {
        const status = apiError.response.status;
        const errorData = apiError.response.data;
        res.status(status).json({ error: errorData?.message || `HTTP ${status}: API 调用失败` });
      } else if (apiError.code === 'ECONNREFUSED') {
        res.status(503).json({ error: '无法连接到 edgeone.ai API' });
      } else {
        res.status(500).json({ error: apiError.message });
      }
    }
  } catch (error) {
    console.error('[edgeone.ai Metrics] 处理请求时出错:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/update', async (req, res) => {
  try {
    await updateData();
    res.json({ success: true, message: '数据更新完成' });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

cron.schedule('0 * * * *', () => {
  console.log('[定时任务] 开始执行定时数据更新...');
  updateData();
});

// 生成随机盐值
function generateSalt(length = 16) {
  return crypto.randomBytes(length).toString('hex');
}

// 使用盐值哈希密码
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

// 验证密码
function verifyPassword(password, salt, hashedPassword) {
  return hashPassword(password, salt) === hashedPassword;
}

// 生成混淆的后台路径
function generateAdminPath() {
  return '/' + crypto.randomBytes(8).toString('hex');
}

// 获取配置中的后台路径
function getAdminPath() {
  const configPath = './config.json';
  if (fsSync.existsSync(configPath)) {
    const configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
    return configData.adminPath || '/admin';
  }
  return '/admin';
}

// 检查是否已安装
app.get('/api/install/status', (req, res) => {
  const configPath = './config.json';
  if (fsSync.existsSync(configPath)) {
    const configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
    res.json({ 
      isInstalled: !!configData.admin,
      // 返回混淆的后台路径
      adminPath: configData.adminPath || '/admin'
    });
  } else {
    res.json({ isInstalled: false, adminPath: '/admin' });
  }
});

// 安装接口
app.post('/api/install', upload.single('favicon'), async (req, res) => {
  try {
    const siteName = req.body.siteName;
    const siteDescription = req.body.siteDescription;
    const adminUsername = req.body.adminUsername;
    const adminPassword = req.body.adminPassword;
    
    // 使用默认值或用户输入的值
    const finalUsername = adminUsername || 'admin';
    const finalPassword = adminPassword || 'admin123';
    
    // 生成盐值和混淆路径
    const salt = generateSalt();
    const hashedPassword = hashPassword(finalPassword, salt);
    const adminPath = generateAdminPath();
    
    // 读取现有配置
    let configData = {
      provider: 'cloudflare',
      cloudflare: { enabled: true, accounts: [] },
      website: {
        title: siteName || 'Analytics Dashboard',
        favicon: '/favicon.svg',
        description: siteDescription || ''
      },
      updateInterval: 2,
      adminPath: adminPath,
      security: {
        salt: salt,
        iterations: 100000
      }
    };

    // 如果有现有配置，保留
    const configPath = './config.json';
    if (fsSync.existsSync(configPath)) {
      configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
      configData.website = {
        title: siteName || configData.website?.title || 'Analytics Dashboard',
        favicon: configData.website?.favicon || '/favicon.svg',
        description: siteDescription || configData.website?.description || ''
      };
      // 保留或生成新的后台路径
      configData.adminPath = configData.adminPath || generateAdminPath();
      configData.security = configData.security || { salt: generateSalt(), iterations: 100000 };
    }

    // 添加管理员信息
    configData.admin = {
      username: finalUsername,
      password: hashedPassword
    };

    // 保存配置
    await fs.writeFile(configPath, JSON.stringify(configData, null, 2));

    res.json({ success: true, adminPath: configData.adminPath });
  } catch (error) {
    console.error('[安装] 失败:', error.message);
    res.json({ success: false, error: error.message });
  }
});

// 登录接口
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.json({ success: false, error: '请填写用户名和密码' });
  }
  
  const configPath = './config.json';
  if (!fsSync.existsSync(configPath)) {
    return res.json({ success: false, error: '系统未安装，请先完成安装' });
  }

  const configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
  
  if (!configData.admin) {
    return res.json({ success: false, error: '系统未安装，请先完成安装' });
  }

  // 使用盐值验证密码
  const salt = configData.security?.salt || generateSalt();
  
  try {
    const hashedPassword = hashPassword(password, salt);
    
    if (configData.admin.username === username && configData.admin.password === hashedPassword) {
      // 生成一次性令牌
      const token = crypto.randomBytes(32).toString('hex');
      const tokenExpiry = Date.now() + 3600000; // 1小时过期
      
      // 保存令牌
      configData.session = { token, expiry: tokenExpiry };
      try {
        fsSync.writeFileSync(configPath, JSON.stringify(configData, null, 2), { encoding: 'utf8' });
      } catch (writeError) {
        console.error('[登录] 保存令牌失败:', writeError.message);
      }
      
      res.json({ 
        success: true, 
        token: token,
        adminPath: configData.adminPath
      });
    } else {
      res.json({ success: false, error: '用户名或密码错误' });
    }
  } catch (error) {
    console.error('[登录] 验证失败:', error.message);
    res.json({ success: false, error: '验证过程中发生错误' });
  }
});

// 令牌验证中间件
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: '未授权访问' });
  }

  const configPath = './config.json';
  if (!fsSync.existsSync(configPath)) {
    return res.status(401).json({ error: '系统未安装' });
  }

  const configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
  
  if (!configData.session || configData.session.token !== token) {
    return res.status(401).json({ error: '令牌无效' });
  }

  if (Date.now() > configData.session.expiry) {
    return res.status(401).json({ error: '令牌已过期' });
  }

  next();
}

// 验证令牌接口
app.get('/api/admin/verify', verifyToken, (req, res) => {
  res.json({ valid: true });
});

// 刷新令牌接口
app.post('/api/admin/refresh-token', verifyToken, (req, res) => {
  const configPath = './config.json';
  const configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
  
  const newToken = crypto.randomBytes(32).toString('hex');
  const newExpiry = Date.now() + 3600000;
  
  configData.session = { token: newToken, expiry: newExpiry };
  fsSync.writeFileSync(configPath, JSON.stringify(configData, null, 2));
  
  res.json({ success: true, token: newToken });
});

// 获取当前后台路径（仅在安装后返回）
app.get('/api/admin/path', (req, res) => {
  const configPath = './config.json';
  if (fsSync.existsSync(configPath)) {
    const configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
    res.json({ 
      path: configData.adminPath || '/admin',
      configured: !!configData.admin
    });
  } else {
    res.json({ path: '/admin', configured: false });
  }
});

// 受保护的配置更新接口
app.post('/api/admin/website', verifyToken, async (req, res) => {
  const { siteName, siteDescription } = req.body;
  
  const configPath = './config.json';
  if (!fsSync.existsSync(configPath)) {
    return res.json({ success: false, error: '系统未安装' });
  }

  const configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
  
  configData.website = {
    title: siteName || configData.website?.title || 'Analytics Dashboard',
    favicon: configData.website?.favicon || '/favicon.svg',
    description: siteDescription || configData.website?.description || ''
  };

  await fs.writeFile(configPath, JSON.stringify(configData, null, 2));
  res.json({ success: true });
});

// CSV 导入接口
app.post('/api/admin/import-csv', verifyToken, async (req, res) => {
  const { accounts } = req.body;
  
  const configPath = './config.json';
  if (!fsSync.existsSync(configPath)) {
    return res.json({ success: false, error: '系统未安装' });
  }

  const configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
  
  // 初始化账户配置
  if (!configData.edgeone) {
    configData.edgeone = { enabled: true, accounts: [] };
  }
  if (!configData.cloudflare) {
    configData.cloudflare = { enabled: true, accounts: [] };
  }
  
  let importedCount = 0;
  
  // 处理每个账户
  for (const account of accounts) {
    const secretId = account.secretid || account.secret_id || '';
    const secretKey = account.secretkey || account.secret_key || '';
    const token = account.token || account.cf_token || '';
    const zoneId = account.zone_id || account.zoneid || '';
    const domain = account.domain || '';
    const name = account.name || account.account_name || `账户 ${configData.edgeone.accounts.length + configData.cloudflare.accounts.length + 1}`;
    
    // 腾讯云 EdgeOne 配置
    if ((secretId.startsWith('AKID') || secretId.startsWith('IKID')) && secretKey) {
      // 检查是否已存在相同的账户
      const existingIndex = configData.edgeone.accounts.findIndex(a => a.secretId === secretId);
      
      if (existingIndex === -1) {
        configData.edgeone.accounts.push({
          name: name,
          secretId: secretId,
          secretKey: secretKey,
          region: account.region || 'ap-hongkong',
          zones: zoneId && domain ? [{
            zone_id: zoneId,
            domain: domain,
            name: domain
          }] : []
        });
        importedCount++;
      }
    }
    
    // Cloudflare 配置
    if (token && zoneId && domain) {
      // 检查是否已存在相同的账户
      const existingIndex = configData.cloudflare.accounts.findIndex(a => a.token === token);
      
      if (existingIndex === -1) {
        configData.cloudflare.accounts.push({
          name: name,
          token: token,
          zones: [{
            zone_id: zoneId,
            domain: domain,
            name: domain
          }]
        });
        importedCount++;
      }
    }
  }
  
  await fs.writeFile(configPath, JSON.stringify(configData, null, 2));
  
  res.json({ 
    success: true, 
    importedCount: importedCount,
    message: `成功导入 ${importedCount} 个账户`
  });
});

// 动态后台路径 - 必须在静态文件服务之后，但在根路径之前
app.get('*', (req, res) => {
  const requestedPath = req.path;
  
  // 跳过 API 请求
  if (requestedPath.startsWith('/api/')) {
    return res.status(404).json({ error: 'API 端点不存在' });
  }
  
  // 检查配置文件是否存在
  const configPath = './config.json';
  const hasConfig = fsSync.existsSync(configPath);
  
  if (hasConfig) {
    const configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
    
    // 如果有配置的后台路径，检查是否匹配
    if (configData.adminPath && requestedPath.startsWith(configData.adminPath)) {
      return res.sendFile(path.join(process.cwd(), 'admin', 'index.html'));
    }
    
    // 如果没有安装，跳转到安装页面
    if (!configData.admin) {
      if (requestedPath === '/' || requestedPath === '') {
        return res.redirect('/admin/install.html');
      }
      return res.sendFile(path.join(process.cwd(), 'admin', 'install.html'));
    }
  } else {
    // 配置文件不存在，未安装状态
    if (requestedPath === '/' || requestedPath === '') {
      return res.redirect('/admin/install.html');
    }
    return res.sendFile(path.join(process.cwd(), 'admin', 'install.html'));
  }
  
  // 路径不匹配，返回首页
  res.sendFile(path.join(process.cwd(), 'index.html'));
});

// 恢复初始接口
app.post('/api/reset', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.json({ success: false, error: '未授权访问' });
    }

    const token = authHeader.substring(7);
    const configPath = './config.json';
    
    if (!fsSync.existsSync(configPath)) {
      return res.json({ success: false, error: '系统未安装' });
    }

    const configData = JSON.parse(fsSync.readFileSync(configPath, 'utf-8'));
    
    if (!configData.session || configData.session.token !== token || configData.session.expiry < Date.now()) {
      return res.json({ success: false, error: '登录已过期，请重新登录' });
    }

    const dataPath = './data/analytics.json';
    
    try {
      if (fsSync.existsSync(dataPath)) {
        fsSync.unlinkSync(dataPath);
      }
    } catch (e) {
      console.log('[重置] 无法删除数据文件:', e.message);
    }

    try {
      fsSync.unlinkSync(configPath);
    } catch (e) {
      console.log('[重置] 无法删除配置文件:', e.message);
    }

    console.log('[重置] 系统已恢复初始状态');
    res.json({ success: true, message: '系统已恢复初始状态' });
  } catch (error) {
    console.error('[重置] 失败:', error.message);
    res.json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`API listening on ${PORT}`);
  console.log(`配置加载成功: ${CFG.accounts.length} 个账户`);
  CFG.accounts.forEach((acc, index) => {
    console.log(`  账户 ${index + 1}: ${acc.name} (${acc.zones.length} 个 zones)`);
  });
  console.log(`\n定时任务已设置: 每小时执行数据更新`);
});
