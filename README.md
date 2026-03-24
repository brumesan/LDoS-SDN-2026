# LDoS-SDN-2026
# Degradação de Desempenho de Contramedidas Estáticas a Ataques de Negação de Serviço de Baixo Volume

Este repositório contém o código-fonte e os experimentos apresentados no artigo aceito no Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC 2026).

## Descrição
O projeto avalia o impacto de ataques de negação de serviço de baixo volume (LDoS) em redes definidas por software (SDN) e como contramedidas estáticas sofrem degradação de desempenho sob diferentes cenários de carga.

## Estrutura do Repositório
* `src/train.py`: Script para treinamento do modelo de detecção (XGBoost).
* `main.py`: Script principal para execução dos testes e coleta de métricas.
* `data/`: Conjunto de dados utilizado nos experimentos.
* `LICENSE`: Licença MIT de código aberto.

## Requisitos
Para reproduzir os experimentos, você precisará de:
* Python 3.8+
* Mininet (Ambiente de rede)
* Bibliotecas listadas em `requirements.txt`

### Instalação
```bash
git clone [https://github.com/brumesan/LDoS-SDN-2026.git](https://github.com/brumesan/LDoS-SDN-2026.git)
cd LDoS-SDN-2026
pip install -r requirements.txt
