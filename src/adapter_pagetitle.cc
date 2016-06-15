/*
 * *********************************************************************
 * adapter_pagetitle.cc
 * v0.1-1 (2016.06.15)
 * by red_neon https://github.com/redneon
 * Squid eCAP PageTitle Logger Module
 * based on adapter_modifying.cc (ecap_adapter_sample-1.0.0) http://e-cap.org/
 * 
 * Logging of titles of html pages into log-file via eCap module for Squid.
 * Support of pages, which compressed via Gzip or Deflate. And you can enable 
 * to keep only these types of compress (see squid.conf settings)
 * Support of page titles with JSON/JSONP callback on sites:
 * 		google.
 * 		yandex.
 * 		go.mail.ru
 * 		youtube.
 *
 * Support of pages with codepages: UTF-8, Windows-1251 (all another will be saved as is)
 * Support of chunked pages (limit 64000 bytes)
 * See README for more information.
 * *********************************************************************
 * Sources:
 * http://www.squid-cache.org/
 * http://e-cap.org/
 * https://github.com/danielaparker/jsoncons
 * https://github.com/Iyamoto/iconv-lite
 * http://windrealm.org/tutorials/decompress-gzip-stream.php
 * *********************************************************************
*/

#include "sample.h"
#include <iostream>
#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/common/named_values.h>
#include <libecap/host/host.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>

/* PAGE_TITLE START */
#include <sstream>
#include <fstream>
#include <time.h>
#include <string.h>
#include <zlib.h>
#include <map>
#include "jsoncons/json.hpp"						// https://github.com/danielaparker/jsoncons
#include "jsoncons_ext/jsonpath/json_query.hpp"		// https://github.com/danielaparker/jsoncons
using jsoncons::json;
using jsoncons::wjson;
using jsoncons::jsonpath::json_query;

std::ofstream log_stream;							// stream for logs
std::ofstream errlog_stream;						// stream for errs
/* PAGE_TITLE END */

/*
 * https://answers.launchpad.net/ecap/+question/277273
 * "virgin" means "coming from the host application to the adapter" (i.e., before adaptation or unaltered)
 * and "adapted" means "coming from the adapter to the host application" (i.e., after adaptation or altered).
 * Please keep in mind that "virgin" and "adapted" are just labels -- the adapter transaction does not
 * have to modify the message it is given. Useful monitoring, read-only adapters do exist.
*/ 



namespace Adapter { // not required, but adds clarity

using libecap::size_type;

class Service: public libecap::adapter::Service {
	public:
		// About
		virtual std::string uri() const; // unique across all vendors
		virtual std::string tag() const; // changes with version and config
		virtual void describe(std::ostream &os) const; // free-format info

		// Configuration
		virtual void configure(const libecap::Options &cfg);
		virtual void reconfigure(const libecap::Options &cfg);
		void setOne(const libecap::Name &name, const libecap::Area &valArea);

		// Lifecycle
		virtual void start(); // expect makeXaction() calls
		virtual void stop(); // no more makeXaction() calls until start()
		virtual void retire(); // no more makeXaction() calls

		// Scope (XXX: this may be changed to look at the whole header)
		virtual bool wantsUrl(const char *url) const;

		// Work
		virtual MadeXactionPointer makeXaction(libecap::host::Xaction *hostx);


	public:
		// Configuration storage
		std::string logfile;						/* PAGE_TITLE */
		std::string errfile;						/* PAGE_TITLE */
		

	protected:
		void setLogfile(const std::string &value);	/* PAGE_TITLE */
};


// Calls Service::setOne() for each host-provided configuration option.
// See Service::configure().
class Cfgtor: public libecap::NamedValueVisitor {
	public:
		Cfgtor(Service &aSvc): svc(aSvc) {}
		virtual void visit(const libecap::Name &name, const libecap::Area &value) {
			svc.setOne(name, value);
		}
		Service &svc;
};


class Xaction: public libecap::adapter::Xaction {
	public:
		Xaction(libecap::shared_ptr<Service> s, libecap::host::Xaction *x);
		virtual ~Xaction();

		// meta-information for the host transaction
		virtual const libecap::Area option(const libecap::Name &name) const;
		virtual void visitEachOption(libecap::NamedValueVisitor &visitor) const;

		// lifecycle
		virtual void start();
		virtual void stop();

		// adapted body transmission control
		virtual void abDiscard();
		virtual void abMake();
		virtual void abMakeMore();
		virtual void abStopMaking();

		// adapted body content extraction and consumption
		virtual libecap::Area abContent(size_type offset, size_type size);
		virtual void abContentShift(size_type size);

		// virgin body state notification
		virtual void noteVbContentDone(bool atEnd);
		virtual void noteVbContentAvailable();

		/* PAGE_TITLE START */
		void log_send(const std::string msg);
		void errlog_send(const std::string msg);
		bool gzipInflate(const std::string& compressedBytes, std::string& uncompressedBytes);
		bool deflateInflate(const std::string& compressedBytes, std::string& uncompressedBytes);
		void cp2utf1(char *out, const char *in);
		std::string cp2utf(std::string s);
		/* PAGE_TITLE END */

	protected:
		void stopVb(); // stops receiving vb (if we are receiving it)
		libecap::host::Xaction *lastHostCall(); // clears hostx

	private:
		libecap::shared_ptr<const Service> service; // configuration access
		libecap::host::Xaction *hostx; // Host transaction rep

		std::string buffer; // for content adaptation

		typedef enum { opUndecided, opOn, opComplete, opNever } OperationState;
		OperationState receivingVb;
		OperationState sendingAb;

		/* PAGE_TITLE START */
		typedef enum { OnStart, OnHtml, OnHead, OnTitle } SearchStatus;
		typedef enum { enc_unk, enc_none, enc_gzip, enc_deflate } EncodingType;
		typedef enum { ct_unk, ct_none, ct_html, ct_json, ct_js } ContentType;
		std::string page_title;
		EncodingType resp_content_encoding;
		ContentType resp_content_type;
		std::string chunk_buffer;	// собираем части пакета в целый
		/* PAGE_TITLE END */
};

static const std::string CfgErrorPrefix =
	"PageTitle Logger module: configuration error: ";

} // namespace Adapter

std::string Adapter::Service::uri() const {
	return "ecap://example.com/ecap_pagetitle";
}

std::string Adapter::Service::tag() const {
	return PACKAGE_VERSION;
}

void Adapter::Service::describe(std::ostream &os) const {
	os << "PageTitle Logger module from " << PACKAGE_NAME << " v" << PACKAGE_VERSION;
}

void Adapter::Service::configure(const libecap::Options &cfg) {
	Cfgtor cfgtor(*this);
	cfg.visitEachOption(cfgtor);

	// check for post-configuration errors and inconsistencies

	if (logfile.empty()) {
		throw libecap::TextException(CfgErrorPrefix +
			"logfile value is not set");
	}
	log_stream.close();
	log_stream.open(logfile.c_str(), std::ofstream::app);
	if (!log_stream.good()) {
		log_stream.close();
		throw libecap::TextException(CfgErrorPrefix +
			"can't open log-file \"" + logfile + "\" in append mode. Check rights!");
	}
	if (!errfile.empty()) {
		errlog_stream.close();
		errlog_stream.open(errfile.c_str(), std::ofstream::app);
		if (!errlog_stream.good()) {
			errlog_stream.close();
			throw libecap::TextException(CfgErrorPrefix +
				"can't open errlog-file \"" + errfile + "\" in append mode. Check rights!");
		}
	}
}

void Adapter::Service::reconfigure(const libecap::Options &cfg) {
	log_stream.close();			/* PAGE_TITLE */
	errlog_stream.close();		/* PAGE_TITLE */
	logfile.clear();			/* PAGE_TITLE */
	errfile.clear();			/* PAGE_TITLE */
	configure(cfg);
}

void Adapter::Service::setOne(const libecap::Name &name, const libecap::Area &valArea) {
	const std::string value = valArea.toString();
	if (name == "logfile")			/* PAGE_TITLE */
		setLogfile(value);			/* PAGE_TITLE */
	else
	if (name.assignedHostId())
		; // skip host-standard options we do not know or care about
	else
		throw libecap::TextException(CfgErrorPrefix +
			"unsupported configuration parameter: " + name.image());
}

void Adapter::Service::setLogfile(const std::string &value) {
	if (value.empty()) {
		throw libecap::TextException(CfgErrorPrefix +
			"empty logfile value is not allowed");
	}
	logfile = value;
//	std:size_t logdir_pos = logfile.find_last_of("/");
//	if (logdir_pos != std::string::npos) {
//		errfile = logfile.substr(0, logdir_pos);
//		errfile += "/page_titles.err";
//	}
}

void Adapter::Service::start() {
	libecap::adapter::Service::start();
	// custom code would go here, but this service does not have one
}

void Adapter::Service::stop() {
	// custom code would go here, but this service does not have one
	libecap::adapter::Service::stop();
}

void Adapter::Service::retire() {
	// custom code would go here, but this service does not have one
	libecap::adapter::Service::stop();
}

bool Adapter::Service::wantsUrl(const char *url) const {
	return true; // no-op is applied to all messages
}

Adapter::Service::MadeXactionPointer
Adapter::Service::makeXaction(libecap::host::Xaction *hostx) {
	return Adapter::Service::MadeXactionPointer(
		new Adapter::Xaction(std::tr1::static_pointer_cast<Service>(self), hostx));
}


Adapter::Xaction::Xaction(libecap::shared_ptr<Service> aService,
	libecap::host::Xaction *x):
	service(aService),
	hostx(x),
	receivingVb(opUndecided), sendingAb(opUndecided) {
}

Adapter::Xaction::~Xaction() {
	if (libecap::host::Xaction *x = hostx) {
		hostx = 0;
		x->adaptationAborted();
	}
}

const libecap::Area Adapter::Xaction::option(const libecap::Name &) const {
	return libecap::Area(); // this transaction has no meta-information
}

void Adapter::Xaction::visitEachOption(libecap::NamedValueVisitor &) const {
	// this transaction has no meta-information to pass to the visitor
}

void Adapter::Xaction::start() {
	Must(hostx);
	if (hostx->virgin().body()) {
		receivingVb = opOn;
		hostx->vbMake(); // ask host to supply virgin body
	} else {
		// we are not interested in vb if there is not one
		receivingVb = opNever;
	}

	/* adapt message header */

	libecap::shared_ptr<libecap::Message> adapted = hostx->virgin().clone();
	Must(adapted != 0);


	/* *** REQUEST MODE *** */
	// разрешаем использовать запросы только со следующими сжатиями: gzip, deflate, identity (как есть)
	typedef const libecap::RequestLine *CLRLP;
	if (CLRLP requestLine = dynamic_cast<CLRLP>(&hostx->virgin().firstLine())) {
		if (!adapted->body()) {
			// accept-encoding
			static const libecap::Name acc_enc_name("Accept-Encoding");
			if (adapted->header().hasAny(acc_enc_name)) {
				const libecap::Header::Value acc_enc_val = adapted->header().value(acc_enc_name);
				std::string acc_enc = acc_enc_val.toString();
				std::string acc_enc_new;
				if (acc_enc.find("gzip") != std::string::npos)
					acc_enc_new = "gzip";
				if (acc_enc.find("deflate") != std::string::npos) {
					if (!acc_enc_new.empty())
						acc_enc_new.append(", ");
					acc_enc_new.append("deflate");
				}
				if (acc_enc.find("identity") != std::string::npos) {
					if (!acc_enc_new.empty())
						acc_enc_new.append(", ");
					acc_enc_new.append("identity");
				}
				adapted->header().removeAny(acc_enc_name);
				if (!acc_enc_new.empty()) {
					const libecap::Header::Value acc_enc_val_new = libecap::Area::FromTempString(acc_enc_new);
					adapted->header().add(acc_enc_name, acc_enc_val_new);
				}
				//libecap::Area uri = requestLine->uri();
				//std::cout << "[start] accept-encoding: old ["<< acc_enc_val <<"] new ["<< acc_enc_new <<"] URL: "<< uri.toString() <<"\n";
			}

			sendingAb = opNever; // there is nothing to send
			lastHostCall()->useAdapted(adapted);
		} else {
			// skip req with body (POST)
			hostx->useVirgin();
			abDiscard();
		}
		return;
	}

	/* *** RESPONSE MODE *** */
	// content-type
	std::string ctype;
	static const libecap::Name content_type_name("Content-Type");
	resp_content_type = ct_unk;
	if (adapted->header().hasAny(content_type_name)) {
		const libecap::Header::Value contentType = adapted->header().value(content_type_name);
		if (contentType.size > 0) {
			ctype = contentType.toString();
			// html
			if(strstr(ctype.c_str(),"text/html"))
				resp_content_type = ct_html;
			// json
			if(strstr(ctype.c_str(),"json"))
				resp_content_type = ct_json;
			// jsonp (json callback)
			if(strstr(ctype.c_str(),"javascript"))
				resp_content_type = ct_js;
		}
	}

	// content-encoding
	std::string enc_type;
	static const libecap::Name content_encoding_name("Content-Encoding");
	resp_content_encoding = enc_unk;
	if (adapted->header().hasAny(content_encoding_name)) {
		const libecap::Header::Value content_encoding = adapted->header().value(content_encoding_name);
		enc_type = content_encoding.toString();
		if (enc_type == "gzip")
			resp_content_encoding = enc_gzip;
		else
		if (enc_type == "deflate")
			resp_content_encoding = enc_deflate;

		//std::cout << "[start] resp_content_encoding ["<< content_encoding.toString() <<"]\n";
	} else
		resp_content_encoding = enc_none;



	if (!adapted->body()) {
		sendingAb = opNever; // there is nothing to send
		lastHostCall()->useAdapted(adapted);
	} else {
		// ignore "bad" content_type, content_encoding
		// exit(status) code
		//libecap::StatusLine &statusLine =dynamic_cast<libecap::StatusLine&>(adapted->firstLine());
		//if ((resp_content_type == ct_unk) || (!((statusLine.statusCode() == 200) || (statusLine.statusCode() == 304))) ) {
		if ((resp_content_type == ct_unk) || (resp_content_encoding == enc_unk)) {
			hostx->useVirgin();
			abDiscard();
		} else {
/*
			// DEBUG
			// get url https://answers.launchpad.net/ecap/+faq/1576
			libecap::Area uri;
			typedef const libecap::RequestLine *CLRLP;
			if (CLRLP requestLine = dynamic_cast<CLRLP>(&hostx->virgin().firstLine()))
					uri = requestLine->uri();
			else
			if (CLRLP requestLine = dynamic_cast<CLRLP>(&hostx->cause().firstLine()))
					uri = requestLine->uri();

			std::string url = uri.toString();
			libecap::Area clientip_m = hostx->option(libecap::metaClientIp);			// https://answers.launchpad.net/ecap/+faq/1516
			static const libecap::Name referer_h("X-Referer");
			const libecap::Area referer = hostx->option(referer_h);
			if (enc_type.empty())
				enc_type = "-";
			std::cout << "[START] "<< clientip_m.toString() <<" [" << enc_type << "] [" << statusLine.statusCode() << "] [" << url.c_str() << "] [" << ctype.c_str() << "] REFERER [" << referer.toString() << "] \n";
*/

			// add a custom header
//			static const libecap::Name name("X-Ecap");
//			const libecap::Header::Value value = libecap::Area::FromTempString("eCAP PageTitile Module");
//			adapted->header().add(name, value);


			page_title.erase();					/* PAGE_TITLE */
			chunk_buffer.erase();				/* PAGE_TITLE */

			// получить начальную часть содержимого до того как будет запущена модицикация
			//const libecap::Area vb = hostx->vbContent(0, libecap::nsize); // get all vb
			//std::string chunk = vb.toString(); // expensive, but simple
			//std::cout << "[" << (unsigned)time(0) << "] start !chunk size! " << chunk.size() << "\n";

			hostx->useAdapted(adapted);
		}
	}
}

void Adapter::Xaction::stop() {
	hostx = 0;
	// the caller will delete
}

void Adapter::Xaction::abDiscard()
{
	Must(sendingAb == opUndecided); // have not started yet
	sendingAb = opNever;
	// we do not need more vb if the host is not interested in ab
	stopVb();
}

void Adapter::Xaction::abMake()
{
	Must(sendingAb == opUndecided); // have not yet started or decided not to send
	Must(hostx->virgin().body()); // that is our only source of ab content

	// we are or were receiving vb
	Must(receivingVb == opOn || receivingVb == opComplete);
	
	sendingAb = opOn;
	if (!buffer.empty())
		hostx->noteAbContentAvailable();
}

void Adapter::Xaction::abMakeMore()
{
	Must(receivingVb == opOn); // a precondition for receiving more vb
	hostx->vbMakeMore();
}

void Adapter::Xaction::abStopMaking()
{
	sendingAb = opComplete;
	// we do not need more vb if the host is not interested in more ab
	stopVb();
}


libecap::Area Adapter::Xaction::abContent(size_type offset, size_type size) {
	Must(sendingAb == opOn || sendingAb == opComplete);
	return libecap::Area::FromTempString(buffer.substr(offset, size));
}

void Adapter::Xaction::abContentShift(size_type size) {
	Must(sendingAb == opOn || sendingAb == opComplete);
	buffer.erase();
	// та часть трафика что уже была отправлено юзеру, тут нам не нужно очищать chunk_buffer
}

void Adapter::Xaction::noteVbContentDone(bool atEnd)
{
// все данные приняты\переданы, все куски буфера собраны, окончание транзакции

//	std::cout << "\n";
//	std::cout << "[noteVbContentDone] start" << std::endl;
//	std::cout << "[noteVbContentDone] chunk_buffer size  "<< chunk_buffer.size() << std::endl;

	std::string chunk_decompressed;
	bool ret = 0;
	switch(resp_content_encoding) {
		case enc_none:
			chunk_decompressed = chunk_buffer;
			break;
		case enc_gzip:
			//std::cout << "[noteVbContentDone] resp_content_encoding gzip....\n";
			if ((!gzipInflate(chunk_buffer, chunk_decompressed)) || (chunk_decompressed.size() == 0)) {
				ret = 1;
//				errlog_send("[noteVbContentDone] decompressed gzip data ERROR!");
			}
			break;
		case enc_deflate:
			//std::cout << "[noteVbContentDone] resp_content_encoding deflate....\n";
			if ((!deflateInflate(chunk_buffer, chunk_decompressed)) || (chunk_decompressed.size() == 0)) {
				ret = 1;
//				errlog_send("[noteVbContentDone] decompressed deflate data ERROR!");
			}
			break;
		default:
//			std::cout << "[noteVbContentDone] unknown encoding type!\n";
			ret = 1;
			break;
	}

	// нет данных, выходим
	if (ret) {
		chunk_buffer.erase();

		Must(receivingVb == opOn);
		stopVb();
		if (sendingAb == opOn) {
			hostx->noteAbContentDone(atEnd);
			sendingAb = opComplete;
		}
//		std::cout <<"[noteVbContentDone] bad comp type, exit"<< std::endl;
		return;
	}

//	std::cout << "[noteVbContentDone] before pagetitle search\n";
	if (resp_content_type == ct_html) {
		const std::string html_l = "<html";
		const std::string html_u = "<HTML";
		const std::string head_l = "<head";
		const std::string head_u = "<HEAD";
		const std::string title_1l = "<title>";
		const std::string title_2l = "</title>";
		const std::string title_1u = "<TITLE>";
		const std::string title_2u = "</TITLE>";
		SearchStatus page_title_state = OnStart;
		std::size_t page_title_pos = 0;
		std::size_t curpos;

		if (((curpos = chunk_decompressed.find(html_l)) != chunk_decompressed.npos) || ((curpos = chunk_decompressed.find(html_u)) != chunk_decompressed.npos)) {
	//		std::cout << page_title_state << ": last_pos | cur_pos " << page_title_pos << " | " << curpos << "\n";
			page_title_state = OnHtml;
			page_title_pos = curpos;
		}
		if (page_title_state == OnHtml) {
			if (((curpos = chunk_decompressed.find(head_l, page_title_pos)) != chunk_decompressed.npos) || ((curpos = chunk_decompressed.find(head_u, page_title_pos)) != chunk_decompressed.npos)) {
	//			std::cout << page_title_state << ": last_pos | cur_pos " << page_title_pos << " | " << curpos << "\n";
				page_title_state = OnHead;
				page_title_pos = curpos;
			}
		}
		if ((page_title_state == OnHead) || (page_title_state == OnStart)) {
			if (((curpos = chunk_decompressed.find(title_1l, page_title_pos)) != chunk_decompressed.npos) || ((curpos = chunk_decompressed.find(title_1u, page_title_pos)) != chunk_decompressed.npos)) {
	//			std::cout << page_title_state << ": last_pos | cur_pos " << page_title_pos << " | " << curpos << "\n";
				page_title_state = OnTitle;
				page_title_pos = curpos;
			}
		}
		if (page_title_state == OnTitle) {
			if (((curpos = chunk_decompressed.find(title_2l, page_title_pos)) != chunk_decompressed.npos) || ((curpos = chunk_decompressed.find(title_2u, page_title_pos)) != chunk_decompressed.npos)) {
	//			std::cout << page_title_state << ": last_pos | cur_pos " << page_title_pos << " | " << curpos << "\n";
				page_title = chunk_decompressed.substr(page_title_pos + 7, curpos - page_title_pos - 7);
			}
		}
	}

	// get current domain
	static const libecap::Name resp_domain("Host");
	std::string resp_domain_val = hostx->cause().header().value(resp_domain).toString();		// cause == response


	/////////////////////// RAW javascript search START --------------//
	struct t_pair {
		std::string str_s;		// string start
		std::string str_e;		// string end
	};
	std::map<std::string, t_pair> raw_titles;
	// google
	raw_titles["google."].str_s = "{\\\"n\\\":\\\"ad\\\",\\\"t\\\":\\\"";
	raw_titles["google."].str_e = "\\\"";
	// yandex
	raw_titles["yandex"].str_s = "function() { var title = \"";
	raw_titles["yandex"].str_e = "\",";
	raw_titles["yandex."].str_s = "el.innerHTML = \"";
	raw_titles["yandex."].str_e = "\";";

	for (auto a = raw_titles.begin(); a != raw_titles.end(); a++) {
		if (resp_domain_val.find(a->first) != std::string::npos) {
			std::size_t raw_start;
			std::size_t raw_end;
			if (((raw_start = chunk_decompressed.find(a->second.str_s)) != chunk_decompressed.npos) &&
			((raw_end = chunk_decompressed.find(a->second.str_e, raw_start + a->second.str_s.size())) != chunk_decompressed.npos)) {
				page_title = chunk_decompressed.substr(raw_start + a->second.str_s.size(), raw_end - raw_start - a->second.str_s.size());
//				std::cout << "[noteVbContentDone] RAW: [" << a->first << "] style founded! \"" << page_title << "\""<< std::endl;
				break;
			}
		}
	}
	/////////////////////// RAW javascript search END ----------------//
	if (page_title.size() == 0) {
		// search JSON
		if ((resp_content_type == ct_json) || (resp_content_type == ct_js)) {
//			std::cout << "[noteVbContentDone] JSON: decode start"<< std::endl;
			json j_content;
			bool is_json = true;		// что бы отличить json от javascript
			std::string chunk_tmp = chunk_decompressed;		// для обрезки jquery тэга вначале яваскрипта

			try { j_content = json::parse(chunk_tmp);
//				std::cout << "[noteVbContentDone] JSON: [0] parsed!!"<< std::endl;
			} catch(const jsoncons::parse_exception& e) {
				// search JSONP
				is_json = false;
//				std::cout << "[noteVbContentDone] JSON: [1] could not parse. Detecting JSONP [1]." << std::endl;
				std::string::size_type j_start;		// start json
				std::string::size_type j_end;
				std::string::size_type js_start;	// start jsonp
				// faster search
				if (((j_start = chunk_decompressed.find_first_of("[{")) != chunk_decompressed.npos) &&
				((j_end = chunk_decompressed.find_last_of("}]")) != chunk_decompressed.npos)) {
					chunk_tmp = chunk_decompressed.substr(j_start, j_end + 1 - j_start);
					is_json = true;
					try { j_content = json::parse(chunk_tmp);
						//std::cout << "[noteVbContentDone] JSON: [2] parsed!! ["<<j_start<<"-"<<j_end<<"]"<< std::endl; } // ":\n"<< j_content << std::endl;
					} catch(const jsoncons::parse_exception& e) {
						is_json = false;
//						std::cout << "[noteVbContentDone] JSON: [2] could not parse. Detecting JSONP [2]." << std::endl;
						// slow search
						// считаем кавычки, чётное число перед нашим шаблоном == все закрыты , ок
						if (
						// если "(" раньше чем "[" или "{" 
						((js_start = chunk_decompressed.find_first_of("(")) != chunk_decompressed.npos) && ((j_start = chunk_decompressed.find_first_of("[{")) != chunk_decompressed.npos)
						&& (js_start < j_start)) {
							//std::cout << "[noteVbContentDone] JSON: [3] JSONP detecting"<< std::endl;
							std::string::size_type fpos = j_start;
							std::string::size_type tot_q = 0;
							while ((j_end = chunk_decompressed.find(")", fpos)) != chunk_decompressed.npos) {
//								std::cout << ">";
								std::string cut_str = chunk_decompressed.substr(fpos, j_end - fpos);
								std::string::size_type qpos = 0;
								//std::cout << "[noteVbContentDone] JSONP detecting....: ["<<j_start<<"-"<<j_end<<"] tot_q[" << tot_q << "] cut_str:\n\n"<< cut_str << "\n" << std::endl;
								while ((qpos = cut_str.find("\"", qpos)) != cut_str.npos) {
//									std::cout << ".";
									tot_q++;
									if ((qpos > 0) && (cut_str.substr(qpos - 1, 1) == "\\")) { 
										tot_q--;
										if ((qpos > 1) && (cut_str.substr(qpos - 2, 1) == "\\"))
											tot_q++;
									}
									qpos++;
								}
								std::string::size_type ost = tot_q % 2;
								if ((ost == 0) && (tot_q != 0)) {
								//	std::cout << "[" << (unsigned)time(0) << "] JSONP detecting....: OK! ["<<j_start<<"-"<<j_end<<"] tot_q[" << tot_q << "] ost[" << ost << "] cut_str see below!" << std::endl;
									break;
								}
								fpos = j_end + 1;
								//std::cout << "[" << (unsigned)time(0) << "] JSONP detecting....: founded wrong \")\"! will next! ["<<j_start<<"-"<<j_end<<"] tot_q[" << tot_q << "] ost[" << ost << "] cut_str see below!\n"; // cut_str:\n\n"<< cut_str << "\n" << std::endl;
							}
//							std::cout << std::endl;
							if (j_end != chunk_decompressed.npos) {
								chunk_tmp = chunk_decompressed.substr(j_start , j_end - j_start);
								is_json = true;
								try { j_content = json::parse(chunk_tmp); }
								catch(const jsoncons::parse_exception& e) { is_json = false; }
//								if (!is_json)
//									std::cout <<"[noteVbContentDone] JSON: [3] could not parse ["<< j_start <<"-"<< j_end <<"]"<< std::endl); // in this:\n"; // << chunk_tmp << std::endl;
//								else
//									std::cout << "[noteVbContentDone] JSON: [3] parsed!! ["<<j_start<<"-"<<j_end<<"] :\n" << j_content << std::endl;
							}
//							else
//								std::cout << "[noteVbContentDone] JSON: [2] end of JSONP not found (not json)" << std::endl;
						}
//						else
//							std::cout << "[noteVbContentDone] JSON: [2.5] could not find JSONP" << std::endl;
					}
				}
//				else
//					std::cout << "[noteVbContentDone] JSON: [2] could not find JSONP" << std::endl;
			}

			// Google			{\"n\":\"bvch\",\"u\":location.href,\"e\":\"9FQ1V6a6HIyasAHWuoeoAw\",\"bvch\":false,\"bv\":24,\"us\":\"c9c918f0\"});\u003C\/script\u003E\u003Cscript\u003Eje.api({\"n\":\"ad\",\"t\":\"123 - Поиск в Google\",
			// Mail.ru 			body:{params:{common: {q: "123", _csp_nonce:
			// Yandex			serp:{params: {found: "123 — Яндекс: нашлось 934 тыс. ответов",…}}
			// Youtube			{"name":"watch","title":"123 - YouTube","

			// Yandex  <script>(function() { var title = "123 — Яндекс: нашлось 88 млн ответов", el = document.createElement("i"); el.innerHTML = title; document.title = el.firstChild.nodeValue; })();</script>
			//"jQuery18309716742819015094_1462989567727(["to",
			// google \u003C\/script\u003E\u003Cscript\u003Eje.api({\"n\":\"ad\",\"t\":\"123 - Поиск в Google\",\"e\":\"-I0zV7P8GcGosgGktoroDw\",\"bc\":\"\"});\u003C\/script
			// youtube  "google.sbox.p50 && google.sbox.p50(["t",[["123",0

			// search title in JSON
			json j_title;
//			bool j_ok = false;
			if (j_content.size() > 0) {
				std::map<std::string, std::string> json_titles = {
					{"google.",			"$.n.t"},
					{"youtube.",		"$[*].title"},
					{"yandex.",			"$.serp.params.found"},
					{"go.mail.ru",		"$.body.params.common.q"},
				};
				for (auto a = json_titles.begin(); a != json_titles.end(); a++) {
					if (resp_domain_val.find(a->first) != std::string::npos) {
						j_title = json_query(j_content, a->second);
//						if (j_title.size() > 0) {
//							std::cout << "[noteVbContentDone] JSON: [" << a->first << "] style founded!" << std::endl;
//							j_ok = true;
//						}
						break;
					}
				}
			}

			if (j_title.size() > 0) {
				page_title = (std::string) j_title.as<std::string>();
				// убираем "[ и ]" из json ответа
				if ((is_json) && (page_title.size() >= 4)) {
					page_title.erase(0, 2);
					page_title.erase(page_title.size() - 2, 2);
					//
					// j_full = json_query(j_content, "$.");
					//std::cout << "json full " << pretty_print(j_full) << std::endl;
				}
			}

			//if (page_title.size() > 0)
			//	std::cout << "[noteVbContentDone] JSON: title \"" << page_title << "\"" << std::endl;
			//else
			//	std::cout << "[noteVbContentDone] JSON: could not find title in:\n" << chunk_tmp << "\n";

		}
////////////////////// JSON PARSER
	}

	if (page_title.length() > 0) {
//		std::cout <<"[noteVbContentDone] pagetitle founded""<< std::endl;
		// дополнительные данные для логов

		/* GET CURRENT URL https://answers.launchpad.net/ecap/+faq/1576 */
		libecap::Area uri;
		typedef const libecap::RequestLine *CLRLP;
		if (CLRLP requestLine = dynamic_cast<CLRLP>(&hostx->virgin().firstLine()))
			uri = requestLine->uri();
		else
		if (CLRLP requestLine = dynamic_cast<CLRLP>(&hostx->cause().firstLine()))
			uri = requestLine->uri();
		std::string url = uri.toString();
	
		static const libecap::Name ctype("Content-Type");
		static const libecap::Name rhost("Host");
		libecap::Area clientip_m = hostx->option(libecap::metaClientIp);			// https://answers.launchpad.net/ecap/+faq/1516
		libecap::Area username_m = hostx->option(libecap::metaUserName);

		std::string ctypeval = hostx->virgin().header().value(ctype).toString();
		std::string rhostval = hostx->cause().header().value(rhost).toString();		// cause == response
		std::string clientip = clientip_m.toString();
		std::string username = username_m.toString();

		// hostx->option в случае отсутствия будет прочерк
		// %<a почему то не передается, а %>la правильный только в прозрачном режиме, в
		// режиме прокси будет айпишник самого прокси.
		static const libecap::Name timestamp_h("X-Squid-Timestamp");
		const libecap::Area timestamp = hostx->option(timestamp_h);
		// Используйте кастомный мета что бы добавить то что вам нужно
		static const libecap::Name custommeta_h("X-PageTitle-Custom");
		const libecap::Area custommeta = hostx->option(custommeta_h);

		// проверяем что бы не было двойной кавычки в поле тип-содержимого
		std::string::size_type ipos = 0;
		while ((ipos = ctypeval.find("\"", ipos)) != std::string::npos) {
			ctypeval.erase(ipos, 1);
		}

		if (ctypeval.empty())
			ctypeval = "-";
		if (rhostval.empty())
			rhostval = "-";
		if (clientip.empty())
			clientip = "-";
		if (username.empty())
			username = "-";

		// convert cp1251 -> utf-8
		if ((ctypeval.find("1251")) != std::string::npos)
			page_title = cp2utf(page_title);

		// ---------- HTML special chars START ---------- //
		// https://en.wikipedia.org/wiki/List_of_XML_and_HTML_character_entity_references
		// только часто встречающиеся
		std::map<std::string, std::string> htmlspec = {
			{"&amp;",   "&"},
			{"&apos;",  "'"},
			{"&quot;",  "″"},	// двойная кавычка заменена на двойной штрих, для соответствия с логами
			{"&gt;",    ">"},
			{"&lt;",    "<"},
			{"&raquo;", "»"},
			{"&laquo;", "«"},
			{"&ndash;", "–"},
			{"&mdash;", "—"},
			{"&nbsp;",  " "},
		};
		for (auto a = htmlspec.begin(); a != htmlspec.end(); a++) {
			std::string::size_type curpos = 0;
			while ((curpos = page_title.find(a->first)) != std::string::npos) {
				page_title.replace(curpos, a->first.size(), a->second);
			}
		}
		// ---------- HTML special chars END ---------- //
		
		// remove newline (\n) from title
		std::string::size_type pos = 0;
		while ((pos = page_title.find("\n",pos)) != std::string::npos) {
			page_title.erase(pos, 1);
		}
		page_title = page_title.substr(0, 254);			// limit length of title
		// Изменение заголовка на этом этапе не работает
		// нельзя добавить например переменную X-PageTitle с нашим результатом,
		// и потом прочитать ее в сквиде и отправить в логи в заголовок, т.к.
		// уже идет процесс изменения содержимого, а
		// измененный заголовок уже передался.
		// Изменять заголовок можно только в функции start,
		// до команды hostx->useAdapted(adapted) или hostx->useVirgin();
		// Точно так же на этом этапе нельзя отправить и мета данные
		// поэтому создаем свой лог-файл 
		log_send(timestamp.toString() + " " + clientip + " " + username + " " + rhostval + " \"" + page_title + "\" " + url + " \"" + ctypeval + "\" " + custommeta.toString() + "");
	}

	// буфер больше не нужен, очищаем его
	//std::cout << "[noteVbContentDone] chunk_buffer size before erase " << chunk_buffer.size() << "\n";
	chunk_buffer.erase();
	
	Must(receivingVb == opOn);
	stopVb();
	if (sendingAb == opOn) {
		hostx->noteAbContentDone(atEnd);
		sendingAb = opComplete;
	}

//	std::cout <<"[noteVbContentDone] exit"<< std::endl;
}

void Adapter::Xaction::noteVbContentAvailable()
{
	// в этой функции проходят содержимое пакетов по частям (если пакет большой или используется chunked)
	// пакет можно собрать целиком и он будет доступн по окончании передачи в функции  void Adapter::Xaction::noteVbContentDone(bool atEnd),
	// где atEnd == true значит передался без ошибок, false - значит был прерван или ошибки
//	std::cout <<"[noteVbContentAvailable] start"<< std::endl;
	Must(receivingVb == opOn);

	const libecap::Area vb = hostx->vbContent(0, libecap::nsize); // get all vb
	std::string chunk = vb.toString(); // expensive, but simple
	hostx->vbContentShift(vb.size); // we have a copy; do not need vb any more
	buffer += chunk; // buffer what we got

	// chunk_buffer - наш буфер, собранный из поделенных частей пакета
	// контролируем размер буфера
	if (chunk_buffer.size() < 64000)
		chunk_buffer.append(chunk);

	//std::cout << "[" << (unsigned)time(0) << "] noteVbContentAvailable chunk size        " << chunk.size() << "\n";
	//std::cout << "[" << (unsigned)time(0) << "] noteVbContentAvailable chunk_buffer size " << chunk_buffer.size() << "\n";
	//std::cout << "|";
	
	if (sendingAb == opOn)
		hostx->noteAbContentAvailable();

//	std::cout <<"[noteVbContentAvailable] exit"<< std::endl;
}

// tells the host that we are not interested in [more] vb
// if the host does not know that already
void Adapter::Xaction::stopVb() {
	if (receivingVb == opOn) {
		hostx->vbStopMaking(); // we will not call vbContent() any more
		receivingVb = opComplete;
	} else {
		// we already got the entire body or refused it earlier
		Must(receivingVb != opUndecided);
	}
}

// this method is used to make the last call to hostx transaction
// last call may delete adapter transaction if the host no longer needs it
// TODO: replace with hostx-independent "done" method
libecap::host::Xaction *Adapter::Xaction::lastHostCall() {
	libecap::host::Xaction *x = hostx;
	Must(x);
	hostx = 0;
	return x;
}

// create the adapter and register with libecap to reach the host application
static const bool Registered =
	libecap::RegisterVersionedService(new Adapter::Service);

//====================================================================//
// this function not used at this time...
void Adapter::Xaction::errlog_send(const std::string msg) {
	char retbuff[255];
	struct timeval timehere;
	gettimeofday(&timehere, NULL);
	strftime(retbuff, 20, "%Y-%m-%d %H:%M:%S", localtime(&timehere.tv_sec));
	snprintf(retbuff + strlen(retbuff), 40 - strlen(retbuff), ".%06ld", timehere.tv_usec);


	// get url https://answers.launchpad.net/ecap/+faq/1576
	libecap::Area uri;
	typedef const libecap::RequestLine *CLRLP;
	if (CLRLP requestLine = dynamic_cast<CLRLP>(&hostx->virgin().firstLine()))
			uri = requestLine->uri();
	else
	if (CLRLP requestLine = dynamic_cast<CLRLP>(&hostx->cause().firstLine()))
			uri = requestLine->uri();

	std::string url = uri.toString();
	libecap::Area clientip_m = hostx->option(libecap::metaClientIp);			// https://answers.launchpad.net/ecap/+faq/1516
	static const libecap::Name referer_h("X-Referer");
	const libecap::Area referer = hostx->option(referer_h);

	std::stringstream ss;
	ss << "[" << retbuff << "] Event: \"" << msg << "\" on URL [" << url.c_str() << "] from IP "<< clientip_m.toString() <<" referer [" << referer.toString() << "]" << std::endl;
	std::cerr << ss.str();

	
	const std::string &errfile = service->errfile;
	if (!errfile.empty()) {
//		std::ofstream errlog_stream;	// поток для записи логов ошибок
		if (!errlog_stream.is_open())
			errlog_stream.open(errfile.c_str(), std::ofstream::app);
		if (!errlog_stream.good()) {
			errlog_stream.close();
			errlog_stream.open(errfile.c_str(), std::ofstream::app);
			if (!errlog_stream.good()) {
				std::cerr << "[" << (unsigned)time(0) << "][ERROR] Can't open errlog-file \"" << errfile.c_str() << "\" in append mode. Check rights! Continue without logs." << std::endl;
				return;
			}
		}
		errlog_stream << ss.str();
//		errlog_stream.close();
	}
}

void Adapter::Xaction::log_send(const std::string msg) {
// никак нельзя отследить ошибку если файл был удален через rm
// для правильной работы ротации лога нужно делать mv , а затем -k reconfigure (-k rotate делает переоткрытие только логов сквида)
	const std::string &logfile = service->logfile;
//	ofstream &log_stream = service->log_stream;
	if (!log_stream.good()) {
		log_stream.close();
		log_stream.open(logfile.c_str(), std::ofstream::app);
		if (!log_stream.good()) {
			std::cerr << "[" << (unsigned)time(0) << "][ERROR] Can't open log-file \"" << logfile.c_str() << "\" in append mode. Check rights! Continue without logs." << std::endl;
			return;
		}
	}
	log_stream << msg << std::endl;
}

//====================================================================//
// from http://windrealm.org/tutorials/decompress-gzip-stream.php
bool Adapter::Xaction::gzipInflate( const std::string& compressedBytes, std::string& uncompressedBytes ) {
	if ( compressedBytes.size() == 0 ) {
		uncompressedBytes = compressedBytes ;
		return true ;
	}

	uncompressedBytes.clear() ;

	unsigned full_length = compressedBytes.size() ;
	unsigned half_length = compressedBytes.size() / 2;

	unsigned uncompLength = full_length ;
	char* uncomp = (char*) calloc( sizeof(char), uncompLength );

	z_stream strm;
	strm.next_in = (Bytef *) compressedBytes.c_str();
	strm.avail_in = compressedBytes.size() ;
	strm.total_out = 0;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;

	bool done = false ;

	if (inflateInit2(&strm, (16+MAX_WBITS)) != Z_OK) {
		free( uncomp );
		return false;
	}

	while (!done) {
		// If our output buffer is too small
		if (strm.total_out >= uncompLength ) {
			// Increase size of output buffer
			char* uncomp2 = (char*) calloc( sizeof(char), uncompLength + half_length );
			memcpy( uncomp2, uncomp, uncompLength );
			uncompLength += half_length ;
			free( uncomp );
			uncomp = uncomp2 ;
		}

		strm.next_out = (Bytef *) (uncomp + strm.total_out);
		strm.avail_out = uncompLength - strm.total_out;

		// Inflate another chunk.
		int err = inflate (&strm, Z_SYNC_FLUSH);
		if (err == Z_STREAM_END) done = true;
		else if (err != Z_OK)  {
			break;
		}
	}

	if (inflateEnd (&strm) != Z_OK) {
		free( uncomp );
		return false;
	}

	for ( size_t i=0; i<strm.total_out; ++i ) {
		uncompressedBytes += uncomp[ i ];
	}
	free( uncomp );
	return true ;
}

bool Adapter::Xaction::deflateInflate( const std::string& compressedBytes, std::string& uncompressedBytes ) {
	if ( compressedBytes.size() == 0 ) {
		uncompressedBytes = compressedBytes ;
		return true ;
	}

	uncompressedBytes.clear() ;

	unsigned full_length = compressedBytes.size() ;
	unsigned half_length = compressedBytes.size() / 2;

	unsigned uncompLength = full_length ;
	char* uncomp = (char*) calloc( sizeof(char), uncompLength );

	z_stream strm;
	strm.next_in = (Bytef *) compressedBytes.c_str();
	strm.avail_in = compressedBytes.size() ;
	strm.total_out = 0;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;

	bool done = false ;

	if (inflateInit(&strm) != Z_OK) {
		free( uncomp );
		return false;
	}

	while (!done) {
		// If our output buffer is too small
		if (strm.total_out >= uncompLength ) {
			// Increase size of output buffer
			char* uncomp2 = (char*) calloc( sizeof(char), uncompLength + half_length );
			memcpy( uncomp2, uncomp, uncompLength );
			uncompLength += half_length ;
			free( uncomp );
			uncomp = uncomp2 ;
		}

		strm.next_out = (Bytef *) (uncomp + strm.total_out);
		strm.avail_out = uncompLength - strm.total_out;

		// Inflate another chunk.
		int err = inflate (&strm, Z_SYNC_FLUSH);
		if (err == Z_STREAM_END) done = true;
		else if (err != Z_OK)  {
			break;
		}
	}

	if (inflateEnd (&strm) != Z_OK) {
		free( uncomp );
		return false;
	}

	for ( size_t i=0; i<strm.total_out; ++i ) {
		uncompressedBytes += uncomp[ i ];
	}
	free( uncomp );
	return true ;
}
//====================================================================//
// from https://github.com/Iyamoto/iconv-lite
void Adapter::Xaction::cp2utf1(char *out, const char *in) {
	static const int table[128] = {
		0x82D0,0x83D0,0x9A80E2,0x93D1,0x9E80E2,0xA680E2,0xA080E2,0xA180E2,
		0xAC82E2,0xB080E2,0x89D0,0xB980E2,0x8AD0,0x8CD0,0x8BD0,0x8FD0,
		0x92D1,0x9880E2,0x9980E2,0x9C80E2,0x9D80E2,0xA280E2,0x9380E2,0x9480E2,
		0,0xA284E2,0x99D1,0xBA80E2,0x9AD1,0x9CD1,0x9BD1,0x9FD1,
		0xA0C2,0x8ED0,0x9ED1,0x88D0,0xA4C2,0x90D2,0xA6C2,0xA7C2,
		0x81D0,0xA9C2,0x84D0,0xABC2,0xACC2,0xADC2,0xAEC2,0x87D0,
		0xB0C2,0xB1C2,0x86D0,0x96D1,0x91D2,0xB5C2,0xB6C2,0xB7C2,
		0x91D1,0x9684E2,0x94D1,0xBBC2,0x98D1,0x85D0,0x95D1,0x97D1,
		0x90D0,0x91D0,0x92D0,0x93D0,0x94D0,0x95D0,0x96D0,0x97D0,
		0x98D0,0x99D0,0x9AD0,0x9BD0,0x9CD0,0x9DD0,0x9ED0,0x9FD0,
		0xA0D0,0xA1D0,0xA2D0,0xA3D0,0xA4D0,0xA5D0,0xA6D0,0xA7D0,
		0xA8D0,0xA9D0,0xAAD0,0xABD0,0xACD0,0xADD0,0xAED0,0xAFD0,
		0xB0D0,0xB1D0,0xB2D0,0xB3D0,0xB4D0,0xB5D0,0xB6D0,0xB7D0,
		0xB8D0,0xB9D0,0xBAD0,0xBBD0,0xBCD0,0xBDD0,0xBED0,0xBFD0,
		0x80D1,0x81D1,0x82D1,0x83D1,0x84D1,0x85D1,0x86D1,0x87D1,
		0x88D1,0x89D1,0x8AD1,0x8BD1,0x8CD1,0x8DD1,0x8ED1,0x8FD1
	};
	while (*in)
		if (*in & 0x80) {
			int v = table[(int)(0x7f & *in++)];
			if (!v)
				continue;
			*out++ = (char)v;
			*out++ = (char)(v >> 8);
			if (v >>= 16)
				*out++ = (char)v;
		}
		else
			*out++ = *in++;
	*out = 0;
}
std::string Adapter::Xaction::cp2utf(std::string s) {
	int c,i;
	int len = s.size();
	std::string ns;
	for(i=0; i<len; i++) {
		c=s[i];
		char buf[4], in[2] = {0, 0};
		*in = c;
		cp2utf1(buf, in);
		ns+=std::string(buf);
	}
	return ns;
}
//====================================================================//

