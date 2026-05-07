# RAG 效果评估报告

生成时间: 2026-05-07T14:57:20Z
WAF2 地址: http://localhost:8081
数据集类型: csic

## 数据集: csic

样本: 攻击 250 条, 正常 250 条
可比性(LLM Errors=0): NO

| 指标 | RAG OFF | RAG ON | 变化 |
|------|---------|--------|------|
| Precision | 1.000 | 1.000 | +0.000 |
| Recall | 0.744 | 0.744 | +0.000 |
| F1 | 0.853 | 0.853 | +0.000 |
| FPR | 0.000 | 0.000 | +0.000 |
| TP | 186 | 186 | +0 |
| FP | 0 | 0 | +0 |
| TN | 250 | 250 | +0 |
| FN | 64 | 64 | +0 |
| Upstream 4xx | 0 | 0 | +0 |
| Upstream 5xx | 0 | 0 | +0 |
| LLM Errors | 2 | 2 | +0 |
| Parse Failed | 0 | 0 | +0 |
| RAG Queries | 0 | 27 | +27 |
| RAG Hits | 0 | 6 | +6 |
| RAG Empty Results | 0 | 21 | +21 |
| RAG Gated | 0 | 6 | +6 |
| RAG Positive Evidence | 0 | 6 | +6 |
| RAG Benign Evidence | 0 | 0 | +0 |
| Route Static Block | 169 | 169 | +0 |
| Route Fast Pass | 126 | 126 | +0 |
| Route Local LLM | 25 | 25 | +0 |
| Route ReAct | 2 | 2 | +0 |
| Local Score Direct Blocks | 163 | 163 | +0 |

### 失败样本预览

- RAG OFF failures: 64
- RAG ON failures: 64

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
- `false_negative` `GET` `/tienda1/publico/registro.jsp.java` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=registro+&login=carringt&password=pis7ar&nombre=Tristana&apellidos=Isart+Viva&email=rae%40ajuntamentbarcelona20.kg&dni=47182191Z&direccion=C%2F+Argullos+73%2C+9%3FA&ciudad=...`
- `false_negative` `GET` `/tienda1/publico/entrar.jsp?errorMsg=Credenciales+incorrectas%2500` status=200 category=- reason=- body=``
- `false_negative` `GET` `/admin/login.do` status=200 category=- reason=- body=``
- `false_negative` `GET` `/` status=200 category=- reason=- body=``
- `false_negative` `PUT` `/tienda1/miembros/editar.jsp` status=200 category=- reason=- body=`modo=registro&login=novelia&password=gener7ble&nombre=Mahoma&apellidos=Armend%E1riz+Velichcanich&email=ku-chine%40lawn.mc&dni=09557832K&direccion=Travesia+Ramon+Ba%F1os%2C+15%2C...`
- `false_negative` `GET` `/asf-logo-wide.gif/` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/global/menum.jsp.INC` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/autenticar.jsp?modo=entrar&login=banerjee&pwd=i1ic-%EDneo%7C&remember=on&B1=Entrar` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=registro&login=yokono5&password=8e6d77ador9&nombre=Vince%2Bnt&apellidos=Gochez&email=mott%40hostprofessional.ma&dni=17879103F&direccion=Calle+Nu%F1ez+De+Guzman+24%2C+&ciuda...`
- `false_negative` `GET` `/tienda1/miembros/editar.jsp?modo=registro&login=jozef&password=ve9dErse&nombre=Tahiel&apellidos=Gua%2Bsp%2B+Kiu%2Bhan&email=lemontier%40viajesnacionales.kp&dni=70721027Y&direccion=Calle+Virgen+De+La+Hoz%2C+123+4-B&ci...` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/autenticar.jsp?modo=entrar&login=levon&pwd=ca%F1ucela&remember=off%2F&B1=Entrar` status=200 category=- reason=- body=``
- `false_negative` `GET` `/examplesWebApp/SessionServlet` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/miembros/editar.jsp` status=200 category=- reason=- body=`modo=registro&login=gaye&password=kanTiaNa&nombre=Fructuoso&apellidos=Rodrigo+Ambr%F3s&email=bloom%40ajuntamentbcn2-0.sz&dni=96068417Q&direccion=C%2F+Juan+Sebastian+Elcano+178+&...`
- `false_negative` `GET` `/tienda1/publico/registro.jsp?modo=registro&login=ivanyi0&password=va7e9ianato&nombre=Crescencio&apellidos=Echevarr%EDa+Borras&email=tadio.bixby%40espaciopintor.eh&dni=98763423C&direccion=Torrent+De+Can+Quintana%2C+17...` status=200 category=- reason=- body=``
- `false_negative` `GET` `/asf-logo-wide.gif/` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/miembros/asf-logo-wide.gif.java` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/autenticar.jsp?modo=entrar&login=buzzy&pwd=IMpr37E4197d9&remember=off%2F&B1=Entrar` status=200 category=- reason=- body=``
- ... 其余 34 条见 `failures.jsonl`
