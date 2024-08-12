<!-- @format -->

<p align="center">
  <img src="https://github.com/user-attachments/assets/1503239f-b992-4e11-a61c-d19294b00af4" /><br/><br/>
  <strong>Bootstrapping Remote Secure Key Infrastructure in Python</strong><br/><br/>
  
  <a href="https://python.org/downloads/release/python-3123/">
  <a href="https://python.org/downloads/release/python-3123/">
    <img src="https://img.shields.io/badge/-Python_3.12.3-3776AB?style=for-the-badge&logo=python&logoColor=white">
  </a>
  
  <a href="https://github.com/dermrvn-code/BRSKI-PY">
    <img src="https://img.shields.io/github/last-commit/dermrvn-code/BRSKI-PY?style=for-the-badge">
  </a>

  <a href="https://github.com/dermrvn-code/BRSKI-PY?tab=MIT-1-ov-file#readme">
    <img src="https://img.shields.io/github/license/dermrvn-code/BRSKI-PY?style=for-the-badge">
  </a>

  <img src="https://img.shields.io/badge/Status-Tech_Demo-red?style=for-the-badge">
</p>

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)

## Installation

To install the BRSKI Python Implementation, follow these steps:

1. Clone the repository:

   ```shell
   git clone https://github.com/dermrvn-code/BRSKI-PY
   ```

2. Navigate to the project directory:

   ```shell
   cd BRSKI-PY
   ```

3. Install the required dependencies:

   ```shell
   py install.py
   ```

4. Run the project:

   ```shell
   start_env.bat
   ```

Now you have successfully installed and can use the BRSKI Python Implementation.

## Usage

#### To use the BRSKI Python Implementation, follow these steps:

1. Run the environment in all terminals starting the scripts:

   ```shell
   start_env.bat
   ```

##### To start the Authorithies server

1. Tab into the 'Authorities' directory:

   ```shell
   cd Authorities
   ```

2. Run the Authorities server:

   ```shell
    py AuthoritiesServer.py
   ```

##### To start the MASA server

1. Tab into the 'MASA' directory:

   ```shell
   cd MASA
   ```

2. Run the MASA server:

   ```shell
    py masa.py
   ```

3. Keep the terminal open to keep the server running.

##### To start the Registrar server

1. Start another terminal and tab into the 'Registrar' directory:

   ```shell
   cd Registrar
   ```

2. Run the Registrar server:

   ```shell
    py registrar.py
   ```

3. Keep the terminal open to keep the server running.

##### To start the pledge

1. Start another terminal and tab into the 'Pledge' directory:

   ```shell
   cd Pledge
   ```

2. Run the pledge:

   ```shell
    py pledge.py
   ```

[(Back to top)](#table-of-contents)
