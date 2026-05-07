# RAG 效果评估报告

生成时间: 2026-05-07T13:18:04Z
WAF2 地址: http://localhost:8081
数据集类型: csic

## 数据集: csic

样本: 攻击 100 条, 正常 100 条
可比性(LLM Errors=0): NO

| 指标 | RAG OFF | RAG ON | 变化 |
|------|---------|--------|------|
| Precision | 1.000 | 1.000 | +0.000 |
| Recall | 0.690 | 0.690 | +0.000 |
| F1 | 0.817 | 0.817 | +0.000 |
| FPR | 0.000 | 0.000 | +0.000 |
| TP | 69 | 69 | +0 |
| FP | 0 | 0 | +0 |
| TN | 100 | 100 | +0 |
| FN | 31 | 31 | +0 |
| Upstream 4xx | 0 | 0 | +0 |
| Upstream 5xx | 0 | 0 | +0 |
| LLM Errors | 1 | 1 | +0 |
| Parse Failed | 0 | 0 | +0 |
| RAG Queries | 0 | 8 | +8 |
| RAG Hits | 0 | 4 | +4 |
| RAG Empty Results | 0 | 4 | +4 |
| RAG Gated | 0 | 4 | +4 |
| RAG Positive Evidence | 0 | 4 | +4 |
| RAG Benign Evidence | 0 | 0 | +0 |
| Route Static Block | 63 | 63 | +0 |
| Route Fast Pass | 71 | 71 | +0 |
| Route Local LLM | 7 | 7 | +0 |
| Route ReAct | 1 | 1 | +0 |
| Local Score Direct Blocks | 59 | 59 | +0 |

### 失败样本预览

- RAG OFF failures: 31
- RAG ON failures: 31

#### RAG ON top failures

- `false_negative` `POST` `/tienda1/publico/vaciar.jsp` status=200 category=- reason=- body=`B2=%257C`
- `false_negative` `GET` `/tienda1/publico/pagar.jsp?modo=insertar&precio=%2B&B1=Pasar+por+caja` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/autenticar.jsp` status=200 category=- reason=- body=`modo=entrar&login=je%3Fanes&pwd=arable&remember=on&B1=Entrar`
- `false_negative` `GET` `/tienda1/publico/vaciar.jsp?B2=%257C` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/asf-logo-wide.gif` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/miembros/editar.jsp?modo=registro&login=c%2Fh%27i%2Fabaut&password=rec73210a&nombre=Sant%EDn&apellidos=Blancas+Sol%F3rzano&email=kleeb%40ringringcargo.kp&dni=72097919A&direccion=Pl.+Constitucion%2C+98%2C+&ciu...` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/miembros/editar.jsp` status=200 category=- reason=- body=`modo=registro&login=blodgett&password=1LFiLERer5&nombre=Quiyen&apellidos=Arosteguy+Aymerich&email=hamblin%40nik.com.cn&dni=76091981T&direccion=Carrer+Lli+31+4-B&ciudad=Camprov%E...`
- `false_negative` `POST` `/tienda1/publico/pagar.jsp` status=200 category=- reason=- body=`modo=insertar&precio=3212&B1=Confirmar%2F`
- `false_negative` `GET` `/tienda1/publico/anadir.jsp?id=3&nombre=Jam%F3n+Ib%E9rico&precio=100%2F&cantidad=48&B1=A%F1adir+al+carrito` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/anadir.jsp?id=2&nombre=Jam%F3n%27+Ib%E9ric-%27o&precio=39&cantidad=24&B1=A%F1adir+al+carrito` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/caracteristicas.jsp?id=%22+AND+%221%22%3D%221` status=0 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=registro&login=scanlan&password=2n5fe2ta2a&nombre=Rasmira&apellidos=Pavi%E9+Pool&email=gloves%40sms24h.mk&dni=92795576Y&direccion=C%2F+Venus%2C%2B+60%2C+&ciudad=Ger&cp=2437...`
- `false_negative` `GET` `/tienda1/publico/autenticar.jsp?modo=entrar&login=schlacht&pwd=43s8a&remember=off%2F&B1=Entrar` status=0 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=%2B&login=michaud&password=41g4i1a487ad1&nombre=Enoch&apellidos=Demuner&email=stevensen7%40deltamarina.cat&dni=50873406M&direccion=Emigrante+50%2C+&ciudad=Monroyo&cp=30191&...`
- `false_negative` `POST` `/tienda1/publico/anadir.jsp` status=200 category=- reason=- body=`id=2&nombre=Jam%F3n+Ib%E9rico&precio=85%2F&cantidad=25&B1=A%F1adir+al+carrito`
- `false_negative` `POST` `/tienda1/publico/pagar.jsp` status=200 category=- reason=- body=`modo=insertar&precio=2948%7C&B1=Confirmar`
- `false_negative` `POST` `/tienda1/publico/anadir.jsp` status=200 category=- reason=- body=`id=3&nombre=Queso+Manchego&precio=39%2500&cantidad=9&B1=A%F1adir+al+carrito`
- `false_negative` `GET` `/tienda1/publico/registro.jsp?modo=registro&login=winona&password=pic%F3n&nombre=Nayla&apellidos=Torre+Xu&email=hyer_longdon0%40artforall.mc&dni=83627503D&direccion=Calle+Corbina%2C+100+&ciudad=Hornillos+de+Cameros&cp...` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/4861362529278789730` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/pagar.jsp` status=200 category=- reason=- body=`modo=insertar&precio=2373&B1=Pasar+por+caja%2F`
- `false_negative` `GET` `/tienda1/miembros/editar.jsp?modo=registro&login=carolina&password=paRtICUlaridaD&nombre=Ihor&apellidos=M%FAgica+Vall%E9s&email=urecal8%40espanolynegocios.bu&dni=67961648Y&direccion=Av.+Olimpica%2C+156+&ciudad=Navajas...` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/miembros/editar.jsp?modo=registro&login=cyndi&password=suBurbICaRIo&nombre=Quimey&apellidos=M%FAzquiz+Metauten&email=mars%40visualreality.au&dni=05744913L&direccion=Urbaniz*acio%2Bn+Aguere+192%2C%2B+&ciudad=O...` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/vaciar.jsp` status=200 category=- reason=- body=`B2=Vaciar+carrito%27INJECTED_PARAM`
- `false_negative` `GET` `/tienda1/publico/registro.jsp.java` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=registro+&login=carringt&password=pis7ar&nombre=Tristana&apellidos=Isart+Viva&email=rae%40ajuntamentbarcelona20.kg&dni=47182191Z&direccion=C%2F+Argullos+73%2C+9%3FA&ciudad=...`
- `false_negative` `GET` `/tienda1/publico/entrar.jsp?errorMsg=Credenciales+incorrectas%2500` status=200 category=- reason=- body=``
- `false_negative` `GET` `/admin/login.do` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/anadir.jsp?id=3%2F&nombre=Vino+Rioja&precio=85&cantidad=80&B1=A%F1adir+al+carrito` status=200 category=- reason=- body=``
- `false_negative` `GET` `/` status=200 category=- reason=- body=``
- `false_negative` `PUT` `/tienda1/miembros/editar.jsp` status=200 category=- reason=- body=`modo=registro&login=novelia&password=gener7ble&nombre=Mahoma&apellidos=Armend%E1riz+Velichcanich&email=ku-chine%40lawn.mc&dni=09557832K&direccion=Travesia+Ramon+Ba%F1os%2C+15%2C...`
- ... 其余 1 条见 `failures.jsonl`
