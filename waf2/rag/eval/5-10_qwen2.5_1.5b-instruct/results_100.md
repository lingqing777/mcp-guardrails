# RAG 效果评估报告

生成时间: 2026-05-09T16:03:52Z
WAF2 地址: http://localhost:8081
数据集类型: csic

## 数据集: csic

样本: 攻击 100 条, 正常 100 条
可比性(LLM Errors=0): YES

| 指标 | RAG OFF | RAG ON | 变化 |
|------|---------|--------|------|
| Precision | 1.000 | 1.000 | +0.000 |
| Recall | 0.850 | 0.850 | +0.000 |
| F1 | 0.919 | 0.919 | +0.000 |
| FPR | 0.000 | 0.000 | +0.000 |
| TP | 85 | 85 | +0 |
| FP | 0 | 0 | +0 |
| TN | 100 | 100 | +0 |
| FN | 15 | 15 | +0 |
| Upstream 4xx | 0 | 0 | +0 |
| Upstream 5xx | 0 | 0 | +0 |
| LLM Errors | 0 | 0 | +0 |
| Parse Failed | 0 | 0 | +0 |
| RAG Queries | 0 | 5 | +5 |
| RAG Hits | 0 | 3 | +3 |
| RAG Empty Results | 0 | 2 | +2 |
| RAG Gated | 0 | 3 | +3 |
| RAG Positive Evidence | 0 | 3 | +3 |
| RAG Benign Evidence | 0 | 0 | +0 |
| Route Static Block | 79 | 79 | +0 |
| Route Fast Pass | 58 | 58 | +0 |
| Route Local LLM | 5 | 5 | +0 |
| Route ReAct | 0 | 0 | +0 |
| Local Score Direct Blocks | 78 | 78 | +0 |

### 失败样本预览

- RAG OFF failures: 15
- RAG ON failures: 15

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
