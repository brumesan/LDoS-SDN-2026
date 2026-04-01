# LDoS-SDN-2026
# Degradação de Desempenho de Contramedidas Estáticas a Ataques de Negação de Serviço de Baixo Volume

Este repositório contém o código-fonte e os experimentos apresentados no artigo aceito no Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC 2026).

## Descrição
O projeto avalia o impacto de ataques de negação de serviço de baixo volume (LDoS) em redes definidas por software (SDN) e como contramedidas estáticas sofrem degradação de desempenho sob diferentes cenários, caracterizando deriva de conceito.

Resumo. Sistemas de detecção de intrusão baseados em algoritmos de aprendizado de máquina supervisionado enfrentam limitações decorrentes da dependência da distribuição do tráfego de rede observada na fase de treinamento. Este artigo analisa a robustez do classificador XGBoost frente a ataques de negação de serviço de baixo volume com parâmetros dinâmicos. Os resultados mostram que variações na taxa de transmissão, duração e ciclo do ataque distanciam o tráfego real daquele visto em treino, caracterizando uma deriva de conceito. Esse fenômeno degrada severamente o desempenho de detecção do classificador. Os experimentos demonstram uma redução significativa na revocação e na pontuação F1. Enquanto ambas as métricas mantinham-se inicialmente acima de 96%, após a deriva de conceito e considerando o pior cenário, os valores reduziram para 65,99% e 79,34%, respectivamente. Portanto, contramedidas estáticas falham em generalizar para cenários dinâmicos, exigindo mecanismos de adaptação contínua para preservar a eficácia do classificador.

## Estrutura do Repositório
* `src/train.py`: Script para treinamento do modelo de detecção (XGBoost).
* `src/traffic.py`: Script para geração de tráfego.
* `main.py`: Script principal para execução dos testes e coleta de métricas.
* `data/`: Conjunto de dados utilizado nos experimentos.
* `LICENSE`: Licença MIT de código aberto.

## Selos Considerados
Os autores consideram a avaliação do seguinte selo:
* Artefatos Disponíveis (SeloD)

## Informações Básicas
Os experimentos foram conduzidos em um ambiente emulado de Software-Defined Networking (SDN), utilizando o emulador Mininet integrado a um controlador Ryu. O ambiente permite a reprodução controlada de cenários com tráfego legítimo e ataques Low-Rate Denial of Service (LDoS), com coleta de métricas em tempo real.

## Requisitos de Hardware
Os experimentos foram executados em servidor com as seguintes especificações:
* Processador: 11th Gen Intel(R) Core(TM) i9-11900K @ 3.50GHz
* Memória RAM: 128 GB DDR4 (4 × 32 GB, 3200 MHz)
* Armazenamento: 2TB 
* Sistema Operacional: Linux (Ubuntu 22.04.5 LTS)

A elevada capacidade de memória e processamento foi utilizada para garantir estabilidade experimental e minimizar interferências de contenção de recursos, não sendo estritamente necessária para reprodução dos experimentos.

## Requisitos de Software
* Ambiente Base: Python 3.8+, Mininet, Open vSwitch, Ryu (OpenFlow 1.3), iperf3 (Geração de tráfego) e Socket Python (Geração do Ataque).

## Bibliotecas
* numpy, pandas, joblib, xgboost.

## Preocupações com segurança
A execução dos artefatos não oferece risco de segurança para os avaliadores.

## Instalação.
* Atualização do Sistema
  
sudo apt update && sudo apt upgrade -y

* Instalação de ferramentas básicas
  
sudo apt install -y git python3 python3-pip build-essential iperf3

* Instalação das bibliotecas Python
  
pip3 install numpy pandas scikit-learn xgboost joblib

* Instalação do Mininet, Open vSwitch e utilitários de rede
  
git clone https://github.com/mininet/mininet

cd mininet

sudo ./util/install.sh -a

* Instalação do Controlador Ryu
  
pip3 install ryu

* Permissões
  
sudo chmod -R 755 /home/"user"/mininet/

* Criação do diretório de resultados
  
mkdir -p /home/"user"/mininet/mininet/resuls

* Organização do Projeto
  
Os arquivos devem ser organizados conforme a seguinte estrutura:

/home/<user>/mininet/mininet/
│

├── collector.py

├── train.py

├── traffic.py

├── xgb_model.json

├── scaler.pkl

└── resultados/

## Teste mínimo
Este teste tem como objetivo verificar se o ambiente foi corretamente instalado e se os principais componentes do sistema estão funcionando adequadamente. O teste executa um cenário simplificado com tráfego legítimo e geração automática de dados, permitindo a validação do pipeline completo.

* Limpeza do ambiente
  
sudo mn -c

* Inicialização do controlador
  
ryu-manager ryu.app.simple_switch_13 collector.py

* Execução do cenário
  
sudo python3 traffic.py

* Geração de arquivo CSV
  
/home/"user"/mininet/mininet/results/

## Experimentos.
## Reivindicação #1 – Detecção de ataques LDoS em ambiente SDN
Esta reivindicação demonstra que o sistema proposto é capaz de detectar ataques LDoS em um ambiente SDN, combinando análise estatística de portas com classificação realizada pelo XGBoost.

* Arquivos utilizados: collector.py e traffic.py
* Tempo de duração: 240 segundos
* Execução:
  
sudo mn -c

ryu-manager ryu.app.simple_switch_13 collector.py

sudo python3 traffic.py

* Resultado Esperado:
  
1- Evidências de Estado de porta

2- Classificação do modelo

3- CSV gerado em /home/"user"/mininet/mininet/results/

4- Logs do iperf em /tmp/

