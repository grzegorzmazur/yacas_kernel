/*
 * This file is part of yacas_kernel.
 * Yacas is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesset General Public License as
 * published by the Free Software Foundation, either version 2.1
 * of the License, or (at your option) any later version.
 *
 * Yacas is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with yacas_kernel.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

/* 
 * File:   yacas_kernel.cpp
 * Author: mazur
 *
 * Created on November 6, 2015, 3:10 PM
 */

#include "yacas_kernel.hpp"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <iostream>
#include <fstream>
#include <string>

namespace {
    std::string now()
    {
        using namespace boost::posix_time;

        return to_iso_extended_string(microsec_clock::local_time());
    }
}

YacasKernel::YacasKernel(const std::string& scripts_path, const Json::Value& config):
    _uuid(_uuid_gen()),
    _hb_socket(_ctx, zmqpp::socket_type::reply),
    _iopub_socket(_ctx, zmqpp::socket_type::publish),
    _control_socket(_ctx, zmqpp::socket_type::router),
    _stdin_socket(_ctx, zmqpp::socket_type::router),
    _shell_socket(_ctx, zmqpp::socket_type::router),
    _engine_socket(_ctx, zmqpp::socket_type::pair),
    _auth(config["key"].asString()),
    _execution_count(1),
    _yacas(new CYacas(_side_effects)),
    _engine(scripts_path, _ctx, "inproc://engine")
{
    const std::string transport = config["transport"].asString();
    const std::string ip = config["ip"].asString();

    _hb_socket.bind(transport + "://" + ip + ":" + config["hb_port"].asString());
    _iopub_socket.bind(transport + "://" + ip + ":" + config["iopub_port"].asString());
    _control_socket.bind(transport + "://" + ip + ":" + config["control_port"].asString());
    _stdin_socket.bind(transport + "://" + ip + ":" + config["stdin_port"].asString());
    _shell_socket.bind(transport + "://" + ip + ":" + config["shell_port"].asString());
    _engine_socket.bind("inproc://engine");
}

void YacasKernel::run()
{
    zmqpp::poller poller;
    
    poller.add(_hb_socket);
    poller.add(_control_socket);
    poller.add(_stdin_socket);
    poller.add(_shell_socket);
    poller.add(_iopub_socket);
    poller.add(_engine_socket);
    
    for (;;) {
        poller.poll();
        
        if (poller.has_input(_shell_socket)) {
            zmqpp::message msg;
            _shell_socket.receive(msg);
            _handle_shell(std::move(msg));
        }

        if (poller.has_input(_engine_socket)) {
            zmqpp::message msg;
            _engine_socket.receive(msg);
            _handle_engine(std::move(msg));
        }
    }
}

std::string YacasKernel::_signature(const zmqpp::message& msg)
{
    std::string header_buf;
    msg.get(header_buf, 3);
    std::string parent_header_buf;
    msg.get(parent_header_buf, 4);
    std::string metadata_buf;
    msg.get(metadata_buf, 5);
    std::string content_buf;
    msg.get(content_buf, 6);

    HMAC_SHA256 auth(_auth);
    
    auth.update(header_buf);
    auth.update(parent_header_buf);
    auth.update(metadata_buf);
    auth.update(content_buf);
    
    return auth.hexdigest();
}

void YacasKernel::_send(zmqpp::socket& socket, const std::string& msg_type,
        const std::string& content_buf, const std::string& parent_header_buf,
        const std::string& metadata_buf, const std::string& identities_buf)
{
    Json::Value header;
    header["username"] = "kernel";
    header["version"] = "5.0";
    header["session"] = boost::uuids::to_string(_uuid);
    header["date"]  = now();
    header["msg_id"] = boost::uuids::to_string(_uuid_gen());
    header["msg_type"] = msg_type;
    Json::StreamWriterBuilder builder;
    std::string header_buf = Json::writeString(builder, header);
    
    HMAC_SHA256 auth(_auth);
    
    auth.update(header_buf);
    auth.update(parent_header_buf);
    auth.update(metadata_buf);
    auth.update(content_buf);
    
    zmqpp::message msg;
    msg.add(identities_buf);
    msg.add("<IDS|MSG>");
    msg.add(auth.hexdigest());
    msg.add(header_buf);
    msg.add(parent_header_buf);
    msg.add(metadata_buf);
    msg.add(content_buf);
    
    socket.send(msg);
}



void YacasKernel::_handle_shell(zmqpp::message&& msg)
{
    Json::StreamWriterBuilder builder;
    
    std::string identities_buf;
    msg.get(identities_buf, 0);
    std::string signature_buf;
    msg.get(signature_buf, 2);
    std::string header_buf;
    msg.get(header_buf, 3);
    std::string parent_header_buf;
    msg.get(parent_header_buf, 4);
    std::string metadata_buf;
    msg.get(metadata_buf, 5);
    std::string content_buf;
    msg.get(content_buf, 6);

    if (_signature(msg) != signature_buf)
        throw std::runtime_error("invalid signature");
    
    Json::Reader reader;

    Json::Value header;
    reader.parse(header_buf, header);

    Json::Value content;
    reader.parse(content_buf, content);

    if (header["msg_type"] == "kernel_info_request") {
        Json::Value reply_content;
        reply_content["protocol_version"] = "5.0";
        reply_content["implementation"] = "cyacas";
        reply_content["implementation_version"] = "1.3.6";
        Json::Value language_info;
        language_info["name"] = "yacas";
        language_info["version"] = "1.3.6";
        language_info["mimetype"] = "text/x-yacas";
        language_info["file_extension"] = ".ys";
        reply_content["language_info"] = language_info;
        reply_content["banner"] = "banner";

        _send(_shell_socket, "kernel_info_reply", Json::writeString(builder, reply_content), header_buf, "{}", identities_buf);
    }
    
    if (header["msg_type"] == "execute_request") {

        _execute_requests.insert(std::make_pair(_execution_count, std::move(msg)));
        _engine.submit(_execution_count, content["code"].asString());
        
        Json::Value reply_content;
        reply_content["status"] =  "ok";
        reply_content["execution_count"] = Json::Value::UInt64(_execution_count);
        reply_content["user_variables"] = Json::Value();
        reply_content["payload"] = Json::Value();
        reply_content["user_expressions"] = Json::Value();
        reply_content["data"] = Json::Value();

        Json::Value reply_metadata;
        reply_metadata["dependencies_met"] = true;
        reply_metadata["engine"] = boost::uuids::to_string(_uuid);
        reply_metadata["status"] = "ok";
        reply_metadata["started"] = now();

        _send(_shell_socket, "execute_result", Json::writeString(builder, reply_content), header_buf, Json::writeString(builder, reply_metadata), identities_buf);
        
        _execution_count += 1;
    }
}

void YacasKernel::_handle_engine(const zmqpp::message& msg)
{
    std::string task_info_buf;
    msg.get(task_info_buf, 0);
    
    Json::Value task_info;

    Json::Reader().parse(task_info_buf, task_info);
    
    const zmqpp::message& execute_request = _execute_requests[task_info["id"].asUInt64()];

    std::string identities_buf;
    execute_request.get(identities_buf, 0);
    std::string signature_buf;
    execute_request.get(signature_buf, 2);
    std::string header_buf;
    execute_request.get(header_buf, 3);
    std::string parent_header_buf;
    execute_request.get(parent_header_buf, 4);
    std::string metadata_buf;
    execute_request.get(metadata_buf, 5);
    std::string content_buf;
    execute_request.get(content_buf, 6);

    Json::StreamWriterBuilder builder;

    Json::Value iopub_content_data;
    iopub_content_data["text/plain"] = task_info["result"];

    Json::Value iopub_content;
    iopub_content["execution_count"] = task_info["id"];
    iopub_content["data"] = iopub_content_data;
    iopub_content["metadata"] = "{}";
    _send(_iopub_socket, "execute_result", Json::writeString(builder, iopub_content), header_buf, "{}", identities_buf);
}
