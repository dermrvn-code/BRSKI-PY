import os
import subprocess
import venv


def run_command(command, env=None):
    result = subprocess.run(
        command,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    return result.stdout.decode().strip()


def create_virtualenv(env_path):
    """Create a virtual environment at the specified path."""
    venv.EnvBuilder(with_pip=True).create(env_path)


def install_requirements(env_path, requirements_file):
    """Install requirements from the requirements file into the virtual environment."""
    pip_path = os.path.join(env_path, "Scripts", "pip")
    run_command(f"{pip_path} install -r {requirements_file}")


def main():
    env_path = ".brski_env"

    # Check if virtual environment already exists
    if not os.path.exists(env_path):
        print(f"Creating virtual environment at {env_path}...")
        create_virtualenv(env_path)
    else:
        print(f"Virtual environment {env_path} already exists.")

    # Check for requirements.txt and install dependencies
    if os.path.exists("requirements.txt"):
        print("Installing requirements...")
        install_requirements(env_path, "requirements.txt")
    else:
        print("requirements.txt not found.")

    print(
        "Setup complete. Virtual environment '.brski_env' is ready and dependencies are installed. Run start_env.bat to activate the environment in the command prompt."
    )


if __name__ == "__main__":
    main()
