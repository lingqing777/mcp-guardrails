# RAG 效果评估报告

生成时间: 2026-05-10T10:06:57Z
WAF2 地址: http://localhost:8081
数据集类型: csic

## 数据集: csic

样本: 攻击 250 条, 正常 250 条
可比性(LLM Errors=0): YES

| 指标 | RAG OFF | RAG ON | 变化 |
|------|---------|--------|------|
| Precision | 1.000 | 1.000 | +0.000 |
| Recall | 0.788 | 0.788 | +0.000 |
| F1 | 0.881 | 0.881 | +0.000 |
| FPR | 0.000 | 0.000 | +0.000 |
| TP | 197 | 197 | +0 |
| FP | 0 | 0 | +0 |
| TN | 250 | 250 | +0 |
| FN | 53 | 53 | +0 |
| Upstream 4xx | 0 | 0 | +0 |
| Upstream 5xx | 0 | 0 | +0 |
| LLM Errors | 0 | 0 | +0 |
| Parse Failed | 3 | 2 | -1 |
| RAG Queries | 0 | 26 | +26 |
| RAG Hits | 0 | 6 | +6 |
| RAG Empty Results | 0 | 20 | +20 |
| RAG Gated | 0 | 6 | +6 |
| RAG Positive Evidence | 0 | 6 | +6 |
| RAG Benign Evidence | 0 | 0 | +0 |
| Route Static Block | 182 | 179 | -3 |
| Route Fast Pass | 117 | 117 | +0 |
| Route Local LLM | 24 | 24 | +0 |
| Route ReAct | 2 | 2 | +0 |
| Local Score Direct Blocks | 176 | 173 | -3 |

### 失败样本预览

- RAG OFF failures: 53
- RAG ON failures: 53

#### RAG ON top failures

- `false_negative` `POST` `/tienda1/publico/autenticar.jsp` status=200 category=- reason=- body=`modo=entrar&login=je%3Fanes&pwd=arable&remember=on&B1=Entrar`
- `false_negative` `GET` `/tienda1/asf-logo-wide.gif` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/miembros/editar.jsp?modo=registro&login=c%2Fh%27i%2Fabaut&password=rec73210a&nombre=Sant%EDn&apellidos=Blancas+Sol%F3rzano&email=kleeb%40ringringcargo.kp&dni=72097919A&direccion=Pl.+Constitucion%2C+98%2C+&ciu...` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/miembros/editar.jsp` status=200 category=- reason=- body=`modo=registro&login=blodgett&password=1LFiLERer5&nombre=Quiyen&apellidos=Arosteguy+Aymerich&email=hamblin%40nik.com.cn&dni=76091981T&direccion=Carrer+Lli+31+4-B&ciudad=Camprov%E...`
- `false_negative` `GET` `/tienda1/publico/anadir.jsp?id=2&nombre=Jam%F3n%27+Ib%E9ric-%27o&precio=39&cantidad=24&B1=A%F1adir+al+carrito` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=registro&login=scanlan&password=2n5fe2ta2a&nombre=Rasmira&apellidos=Pavi%E9+Pool&email=gloves%40sms24h.mk&dni=92795576Y&direccion=C%2F+Venus%2C%2B+60%2C+&ciudad=Ger&cp=2437...`
- `false_negative` `GET` `/tienda1/publico/autenticar.jsp?modo=entrar&login=schlacht&pwd=43s8a&remember=off%2F&B1=Entrar` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=%2B&login=michaud&password=41g4i1a487ad1&nombre=Enoch&apellidos=Demuner&email=stevensen7%40deltamarina.cat&dni=50873406M&direccion=Emigrante+50%2C+&ciudad=Monroyo&cp=30191&...`
- `false_negative` `GET` `/tienda1/publico/registro.jsp?modo=registro&login=winona&password=pic%F3n&nombre=Nayla&apellidos=Torre+Xu&email=hyer_longdon0%40artforall.mc&dni=83627503D&direccion=Calle+Corbina%2C+100+&ciudad=Hornillos+de+Cameros&cp...` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/4861362529278789730` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/miembros/editar.jsp?modo=registro&login=carolina&password=paRtICUlaridaD&nombre=Ihor&apellidos=M%FAgica+Vall%E9s&email=urecal8%40espanolynegocios.bu&dni=67961648Y&direccion=Av.+Olimpica%2C+156+&ciudad=Navajas...` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/miembros/editar.jsp?modo=registro&login=cyndi&password=suBurbICaRIo&nombre=Quimey&apellidos=M%FAzquiz+Metauten&email=mars%40visualreality.au&dni=05744913L&direccion=Urbaniz*acio%2Bn+Aguere+192%2C%2B+&ciudad=O...` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=registro+&login=carringt&password=pis7ar&nombre=Tristana&apellidos=Isart+Viva&email=rae%40ajuntamentbarcelona20.kg&dni=47182191Z&direccion=C%2F+Argullos+73%2C+9%3FA&ciudad=...`
- `false_negative` `GET` `/tienda1/publico/entrar.jsp?errorMsg=Credenciales+incorrectas%2500` status=200 category=- reason=- body=``
- `false_negative` `GET` `/` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/autenticar.jsp?modo=entrar&login=banerjee&pwd=i1ic-%EDneo%7C&remember=on&B1=Entrar` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=registro&login=yokono5&password=8e6d77ador9&nombre=Vince%2Bnt&apellidos=Gochez&email=mott%40hostprofessional.ma&dni=17879103F&direccion=Calle+Nu%F1ez+De+Guzman+24%2C+&ciuda...`
- `false_negative` `GET` `/tienda1/miembros/editar.jsp?modo=registro&login=jozef&password=ve9dErse&nombre=Tahiel&apellidos=Gua%2Bsp%2B+Kiu%2Bhan&email=lemontier%40viajesnacionales.kp&dni=70721027Y&direccion=Calle+Virgen+De+La+Hoz%2C+123+4-B&ci...` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/autenticar.jsp?modo=entrar&login=levon&pwd=ca%F1ucela&remember=off%2F&B1=Entrar` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/miembros/editar.jsp` status=200 category=- reason=- body=`modo=registro&login=gaye&password=kanTiaNa&nombre=Fructuoso&apellidos=Rodrigo+Ambr%F3s&email=bloom%40ajuntamentbcn2-0.sz&dni=96068417Q&direccion=C%2F+Juan+Sebastian+Elcano+178+&...`
- `false_negative` `GET` `/tienda1/publico/registro.jsp?modo=registro&login=ivanyi0&password=va7e9ianato&nombre=Crescencio&apellidos=Echevarr%EDa+Borras&email=tadio.bixby%40espaciopintor.eh&dni=98763423C&direccion=Torrent+De+Can+Quintana%2C+17...` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/autenticar.jsp?modo=entrar&login=buzzy&pwd=IMpr37E4197d9&remember=off%2F&B1=Entrar` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=registro&login=bobbette&password=v4N0c76.SE&nombre=Albere&apellidos=Casa+Aro-ca&email=mallalieu%40soymuyguapa.ml&dni=58990935Y&direccion=Pla%E7a+Puerto+Rico%2C+144+&ciudad=...`
- `false_negative` `GET` `/tienda1/imagenes/6909030637832563290.jsp` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/entrar.jsp/4861362529278789730.inc` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/autenticar.jsp` status=200 category=- reason=- body=`modo=entrar&login=chern1&pwd=70staje&remember=on%2F&B1=Entrar`
- `false_negative` `POST` `/tienda1/miembros/editar.jsp` status=200 category=- reason=- body=`modo=registro&login=kathlin&password=%2Blaur938&nombre=Rasmira&apellidos=Pubill+Tena&email=strasberg-gales%40videocasa-ebs.gi&dni=%27OR%27a%3D%27a&direccion=Isla+De+Salvora%2C+6...`
- `false_negative` `POST` `/tienda1/publico/autenticar.jsp` status=200 category=- reason=- body=`modo=entrar&login=wingrove&pwd=e5827&remember=on%22+AND+%221%22%3D%221&B1=Entrar`
- `false_negative` `GET` `/tienda1/miembros/asf-logo-wide` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/miembros/editar.jsp` status=200 category=- reason=- body=`modo=registro&login=gantt&password=sae19r8&nombre=Libe&apellidos=Amusquivar&email=mccormack%40neotelecom.tn&dni=35453403F&direccion=Calle+Tamarindo%2C+118+&ciudad=Cabre%3Fros*+d...`
- ... 其余 23 条见 `failures.jsonl`
