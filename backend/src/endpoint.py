"""
This file is an API implementation for all of the endpoints that the frontend
needs to operate.
    * get-table-headers - Returns the JSON definition aof the table headers to 
      the frontend by calling a user defined fixture.
    * get-properties - Returns a JSON dictionary that defines properties for the 
      frontend like a title, an icon image to display, and color options.
    * get-icon - Return the icon image used by the frontend.
    * fetch - fetches all of the data by running all of the plugins as 
      chains within a DAG. A merge fixture is called after the plugins are run.
"""

# System imports
import importlib.util
import os
import pathlib
from typing import List, Any, Dict, Annotated, Tuple
import shutil
from pathlib import Path
from datetime import datetime
import tempfile
import zipfile

# 3rd party imports
import pluggy
from fastapi.responses import FileResponse
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from prefect import flow
from prefect.futures import wait

# Local imports
from model import AppResult, PluginQuery, PluginResult
from specs import FixtureSpecs, PluginSpecs

# Global variables
APPLICATION_NAME: str = os.getenv("APPLICATION_NAME", "")
KV_STORE: Dict[Any, Any] = {}

# Fast API declarations
origins = ["*"]
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def store_results(data: PluginResult):
    """
    Stores the results of all of the pipeline runs with the Plug-in Name as key.

    Parameters
    ----------
    data : PluginResult
        An individual result of the etl process
    """
    print(f"IN store_results. name={data.plugin_name}; data={data.plugin_data}")
    if data.plugin_name not in KV_STORE:
        KV_STORE[data.plugin_name] = []
    KV_STORE[data.plugin_name].append(data.plugin_data)


def load_plugins_from_dir(pm: pluggy.PluginManager, directory: str):
    """
    Utility function to load all of the plugins from a specified directory.

    Parameters
    ----------
    pm : pluggy.PluginManager
        The plugin managere to store the plugin modules in.

    directory : str
        The name of the directory to load plugins from.
    """
    path = pathlib.Path(directory)
    for file in path.glob("*.py"):
        if file.name == "__init__.py":
            continue

        # Dynamically import the module
        spec = importlib.util.spec_from_file_location(file.stem, file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Register the module with pluggy
        pm.register(module)


@app.post("/upload")
@flow(name="Generator ETL Flow", log_prints=True)
async def upload(start_date: Annotated[str, Form()], end_date: Annotated[str, Form()], time_zone: Annotated[str, Form()], file: UploadFile = File(...)) -> FileResponse:
    """
    Endpoint that fetches all of the data by running all of the plugins as 
    chains within a DAG. A merge fixture is called after the plugins are run.

    Parameters
    ----------
    query : Dict[Any, Any]
        A generic query that has data that the plugin understands.

    Returns
    -------
    AppResult
        A generic result that contains the data after the merge step completed.
    """
    
    global KV_STORE
    
    # Setup Plugin Manager
    pm = pluggy.PluginManager(APPLICATION_NAME + "-plugins")
    pm.add_hookspecs(PluginSpecs)

    # Load plugins from the 'plugins' folder
    plugin_dir = os.getenv("PLUGINS_DIR")
    load_plugins_from_dir(pm, plugin_dir if plugin_dir else "src/plugins")

    plugin_query = PluginQuery[Tuple](data=(start_date, end_date, time_zone, file))

    futures = []
    for name, plugin in pm.list_name_plugin():
        _ = name
        
        # Submit the first task of the chain. 
        # Downstream tasks (transform & load) will execute sequentially 
        # within this chain in parallel with other chains.
        chain_start_future = plugin.extract.submit(plugin_query)
        
        # You can also attach the sequential steps right here
        # Note: If passing futures to sub-tasks, they will wait for the future's result
        t_future = plugin.transform.submit(chain_start_future)
        l_future = plugin.load.submit(t_future)

        futures.append(l_future)
    wait(futures)
    
    for future in futures:
        for result in future.result():
            print(result)
            store_results(result)

    # After the DAG is run and all of the results are collected, the 
    # merge_results fixture is executed to perform final processing.
    fixtures = pluggy.PluginManager(APPLICATION_NAME + "-fixtures")
    fixtures.add_hookspecs(FixtureSpecs)
    fixtures_dir = os.getenv("FIXTURES_DIR")
    load_plugins_from_dir(
        fixtures, fixtures_dir if fixtures_dir else "src/fixtures"
    )
    results = fixtures.hook.merge_results(kv_store=KV_STORE)
    file_path = results[0].data
    KV_STORE = {}

    if file_path:
        return FileResponse(
            path=file_path,
            media_type="application/pdf", 
            filename="downloaded_file.pdf"
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A critical internal service failed"
        )
    

@app.get("/get-table-headers")
def get_table_headers() -> List[Dict[Any, Any]]:
    """
    Endpoint that returns the JSON definition aof the table headers to the
    frontend by calling a user defined fixture.

    Returns
    -------
    List[Dict[Any, Any]]
        A list of objects where each element defines a column for the frontend
        table.
    """
    fixtures = pluggy.PluginManager(APPLICATION_NAME + "-fixtures")
    fixtures.add_hookspecs(FixtureSpecs)
    fixtures_dir = os.getenv("FIXTURES_DIR")
    load_plugins_from_dir(
        fixtures, fixtures_dir if fixtures_dir else "src/fixtures"
    )
    results = fixtures.hook.get_table_headers()
    return results[0]


@app.get("/get-properties")
def get_properties() -> Dict[Any, Any]:
    """
    Endpoint that returns a JSON dictionary that defines properties for the 
    frontend like a title, an icon image to display, and color options.

    Returns
    -------
    Dict[Any, Any]
        A dictionary of various properties.
    """
    fixtures = pluggy.PluginManager(APPLICATION_NAME + "-fixtures")
    fixtures.add_hookspecs(FixtureSpecs)
    fixtures_dir = os.getenv("FIXTURES_DIR")
    load_plugins_from_dir(
        fixtures, fixtures_dir if fixtures_dir else "src/fixtures"
    )
    results = fixtures.hook.get_properties()
    return results[0]


@app.get("/get-icon")
def get_icon() -> str:
    """
    Enpoint that runs a fixture to return the icon image used by the frontend.

    Returns
    -------
    str
        A base64 encoded string of the icon image.
    """
    fixtures = pluggy.PluginManager(APPLICATION_NAME + "-fixtures")
    fixtures.add_hookspecs(FixtureSpecs)
    fixtures_dir = os.getenv("FIXTURES_DIR")
    load_plugins_from_dir(
        fixtures, fixtures_dir if fixtures_dir else "src/fixtures"
    )
    results = fixtures.hook.get_icon()
    return results[0]


if __name__ == "__main__":
    pass