 #!/bin/bash

# Source pyenv and activate the desired virtual environment
export PYENV_ROOT="/home/ec2-user/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

 pyenv local 3.12.11

# Change to your script's directory (optional, but often good practice)
cd /home/ec2-user/repos/saa_grafana

# Execute your Python script
poetry run  python src/analyze.py --batch --influx >> /var/saa/logs/logfile.log 2>&1