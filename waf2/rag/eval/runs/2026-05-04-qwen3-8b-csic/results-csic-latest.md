# RAG 效果评估报告

生成时间: 2026-05-05T15:15:48Z
WAF2 地址: http://localhost:8081
数据集类型: csic

## 数据集: csic

样本: 攻击 250 条, 正常 250 条
可比性(LLM Errors=0): YES

| 指标 | RAG OFF | RAG ON | 变化 |
|------|---------|--------|------|
| Precision | 1.000 | 1.000 | +0.000 |
| Recall | 0.320 | 0.320 | +0.000 |
| F1 | 0.485 | 0.485 | +0.000 |
| FPR | 0.000 | 0.000 | +0.000 |
| TP | 80 | 80 | +0 |
| FP | 0 | 0 | +0 |
| TN | 250 | 250 | +0 |
| FN | 170 | 170 | +0 |
| Upstream 4xx | 0 | 0 | +0 |
| Upstream 5xx | 0 | 0 | +0 |
| LLM Errors | 0 | 0 | +0 |
| Parse Failed | 4 | 8 | +4 |
| RAG Queries | 0 | 46 | +46 |
| RAG Hits | 0 | 15 | +15 |
| RAG Empty Results | 0 | 31 | +31 |
| RAG Gated | 0 | 12 | +12 |
| RAG Positive Evidence | 0 | 15 | +15 |
| RAG Benign Evidence | 0 | 0 | +0 |
| Route Static Block | 74 | 74 | +0 |
| Route Fast Pass | 209 | 209 | +0 |
| Route Local LLM | 43 | 40 | -3 |
| Route ReAct | 3 | 6 | +3 |
| Local Score Direct Blocks | 64 | 64 | +0 |

### 失败样本预览

- RAG OFF failures: 170
- RAG ON failures: 170

#### RAG ON top failures

- `false_negative` `POST` `/tienda1/publico/vaciar.jsp` status=200 category=- reason=- body=`B2A=Vaciar+carrito`
- `false_negative` `POST` `/tienda1/publico/vaciar.jsp` status=200 category=- reason=- body=`B2A=Vaciar+carrito`
- `false_negative` `POST` `/tienda1/publico/entrar.jsp` status=200 category=- reason=- body=`errorMsgA=Credenciales+incorrectas`
- `false_negative` `POST` `/tienda1/publico/anadir.jsp` status=200 category=- reason=- body=`idA=2&nombre=Vino+Rioja&precio=39&cantidad=1&B1=A%F1adir+al+carrito`
- `false_negative` `POST` `/tienda1/publico/vaciar.jsp` status=200 category=- reason=- body=`B2=%257C`
- `false_negative` `POST` `/tienda1/publico/autenticar.jsp` status=200 category=- reason=- body=`modo=entrar&login=dadang&pwd=6a1er87&rememberA=on&B1=Entrar`
- `false_negative` `GET` `/tienda1/publico/pagar.jsp?modo=insertar&precio=%2B&B1=Pasar+por+caja` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/pagar.jsp` status=200 category=- reason=- body=`modo=insertar&precio=7879&B1A=Pasar+por+caja`
- `false_negative` `POST` `/tienda1/publico/autenticar.jsp` status=200 category=- reason=- body=`modo=entrar&login=je%3Fanes&pwd=arable&remember=on&B1=Entrar`
- `false_negative` `GET` `/tienda1/publico/vaciar.jsp?B2=%257C` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/asf-logo-wide.gif` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/caracteristicas.jsp` status=200 category=- reason=- body=`idA=1`
- `false_negative` `GET` `/tienda1/miembros/editar.jsp?modo=registro&login=c%2Fh%27i%2Fabaut&password=rec73210a&nombre=Sant%EDn&apellidos=Blancas+Sol%F3rzano&email=kleeb%40ringringcargo.kp&dni=72097919A&direccion=Pl.+Constitucion%2C+98%2C+&ciu...` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/autenticar.jsp` status=200 category=- reason=- body=`modoA=entrar&login=villella&pwd=5e04ayo&remember=on&B1=Entrar`
- `false_negative` `POST` `/tienda1/miembros/editar.jsp` status=200 category=- reason=- body=`modo=registro&login=blodgett&password=1LFiLERer5&nombre=Quiyen&apellidos=Arosteguy+Aymerich&email=hamblin%40nik.com.cn&dni=76091981T&direccion=Carrer+Lli+31+4-B&ciudad=Camprov%E...`
- `false_negative` `GET` `/tienda1/publico/anadir.jsp?id=3&nombreA=Vino+Rioja&precio=100&cantidad=81&B1=A%F1adir+al+carrito` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/pagar.jsp` status=200 category=- reason=- body=`modoA=insertar&precio=4862&B1=Pasar+por+caja`
- `false_negative` `POST` `/tienda1/publico/pagar.jsp` status=200 category=- reason=- body=`modo=insertar&precio=3212&B1=Confirmar%2F`
- `false_negative` `GET` `/tienda1/publico/registro.jsp?modo=registro&login=kristjan&password=asiria&nombre=Gertrudis&apellidosA=Massafr%E9+Danes&email=perier%40chevrolet-volt.in&dni=39012557A&direccion=Calle+Alfonso+Onceno%2C+167%2C+&ciudad=A...` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/anadir.jsp?id=3&nombre=Jam%F3n+Ib%E9rico&precio=100%2F&cantidad=48&B1=A%F1adir+al+carrito` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/anadir.jsp?id=2&nombre=Jam%F3n%27+Ib%E9ric-%27o&precio=39&cantidad=24&B1=A%F1adir+al+carrito` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/anadir.jsp` status=200 category=- reason=- body=`idA=2&nombre=Jam%F3n+Ib%E9rico&precio=100&cantidad=80&B1=A%F1adir+al+carrito`
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=registro&login=scanlan&password=2n5fe2ta2a&nombre=Rasmira&apellidos=Pavi%E9+Pool&email=gloves%40sms24h.mk&dni=92795576Y&direccion=C%2F+Venus%2C%2B+60%2C+&ciudad=Ger&cp=2437...`
- `false_negative` `GET` `/tienda1/miembros/.BAK` status=200 category=- reason=- body=``
- `false_negative` `GET` `/tienda1/publico/autenticar.jsp?modo=entrar&login=schlacht&pwd=43s8a&remember=off%2F&B1=Entrar` status=200 category=- reason=- body=``
- `false_negative` `POST` `/tienda1/publico/registro.jsp` status=200 category=- reason=- body=`modo=%2B&login=michaud&password=41g4i1a487ad1&nombre=Enoch&apellidos=Demuner&email=stevensen7%40deltamarina.cat&dni=50873406M&direccion=Emigrante+50%2C+&ciudad=Monroyo&cp=30191&...`
- `false_negative` `POST` `/tienda1/publico/autenticar.jsp` status=200 category=- reason=- body=`modo=entrar&loginA=mathews&pwd=6u1ad5&remember=on&B1=Entrar`
- `false_negative` `POST` `/tienda1/miembros/editar.jsp` status=200 category=- reason=- body=`modo=registro&login=gerhart6&password=bote%21ll%F3n&nombre=Imperio&apellidos=Vericat+Planelas&email=nadiuska.tolan%40icodea.cf&dni=91508719E&direccion=Calle+Valencia+113%2C+&ciu...`
- `false_negative` `POST` `/tienda1/publico/anadir.jsp` status=200 category=- reason=- body=`id=2&nombre=Jam%F3n+Ib%E9rico&precio=85%2F&cantidad=25&B1=A%F1adir+al+carrito`
- `false_negative` `POST` `/tienda1/publico/pagar.jsp` status=200 category=- reason=- body=`modo=insertar&precio=2948%7C&B1=Confirmar`
- ... 其余 140 条见 `failures.jsonl`
